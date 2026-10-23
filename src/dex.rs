use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const MAX_FEE_BPS: u16 = 300;
pub const DEFAULT_FEE_BPS: u16 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexPool {
    pub pair_id: String,
    pub token_symbol: String,
    pub anet_reserve_ants: u128,
    pub token_reserve_units: u128,
    pub total_lp_units: u128,
    pub fee_bps: u16,
    pub lp_positions: HashMap<String, u128>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexPoolView {
    pub pair_id: String,
    pub token_symbol: String,
    pub anet_reserve_ants: String,
    pub anet_reserve_anet: String,
    pub token_reserve_units: String,
    pub total_lp_units: String,
    pub fee_bps: u16,
    pub lp_holders: usize,
    pub lp_positions: HashMap<String, String>,
    pub l1_price_discovery: bool,
    pub price_discovery_source: String,
    pub l1_market_scope: String,
    pub l2_price_separate: bool,
    pub spot_token_units_per_anet: String,
    pub spot_anet_ants_per_token_unit: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexQuoteView {
    pub pair_id: String,
    pub direction: String,
    pub amount_in: String,
    pub amount_out: String,
    pub fee_paid: String,
    pub min_out_1pct_slippage: String,
    pub price_impact_bps: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexLiquidityResult {
    pub pair_id: String,
    pub provider: String,
    pub lp_minted: String,
    pub total_lp_units: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexPoolAuditView {
    pub pair_id: String,
    pub token_symbol: String,
    pub creation_block_height: Option<u64>,
    pub creation_block_hash: Option<String>,
    pub creation_event: Option<String>,
    pub creation_source: String,
    pub initial_anet_reserve_ants: String,
    pub initial_token_reserve_units: String,
    pub current_anet_reserve_ants: String,
    pub current_token_reserve_units: String,
    pub current_total_lp_units: String,
    pub lp_providers: Vec<String>,
    pub token_registered: bool,
    pub token_total_supply_units: Option<u64>,
    pub token_pool_escrow_units: Option<u64>,
    pub token_pool_escrow_matches_reserve: bool,
    pub admin_top_up_detected: bool,
    pub post_creation_swap_detected: bool,
    pub reserves_unchanged_since_creation: bool,
    pub onchain_funding_auditable: bool,
    pub external_backing_auditable: bool,
    pub suitable_for_l1_price_discovery: bool,
    pub suitable_for_external_price_discovery: bool,
    pub status: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexRemoveLiquidityResult {
    pub pair_id: String,
    pub provider: String,
    pub lp_burned: String,
    pub anet_amount_ants: String,
    pub token_amount_units: String,
    pub remaining_lp_units: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DexSwapResult {
    pub pair_id: String,
    pub trader: String,
    pub direction: String,
    pub amount_in: String,
    pub amount_out: String,
    pub fee_paid: String,
}

impl DexPool {
    pub fn view(&self, l1_price_discovery: bool) -> DexPoolView {
        DexPoolView {
            pair_id: self.pair_id.clone(),
            token_symbol: self.token_symbol.clone(),
            anet_reserve_ants: self.anet_reserve_ants.to_string(),
            anet_reserve_anet: format_anet_fixed_u128(self.anet_reserve_ants),
            token_reserve_units: self.token_reserve_units.to_string(),
            total_lp_units: self.total_lp_units.to_string(),
            fee_bps: self.fee_bps,
            lp_holders: self.lp_positions.len(),
            lp_positions: self
                .lp_positions
                .iter()
                .map(|(wallet, units)| (wallet.clone(), units.to_string()))
                .collect(),
            l1_price_discovery,
            price_discovery_source: if l1_price_discovery {
                "native_l1_amm_reserves"
            } else {
                "not_a_l1_market"
            }
            .to_owned(),
            l1_market_scope: "native_anet_l1_only".to_owned(),
            l2_price_separate: true,
            spot_token_units_per_anet: spot_token_units_per_anet(
                self.anet_reserve_ants,
                self.token_reserve_units,
            )
            .to_string(),
            spot_anet_ants_per_token_unit: spot_anet_ants_per_token_unit(
                self.anet_reserve_ants,
                self.token_reserve_units,
            )
            .to_string(),
            updated_at: self.updated_at,
        }
    }
}

pub fn pool_key(symbol: &str) -> Result<String> {
    let token = normalize_token_symbol(symbol)?;
    Ok(format!("ANET-{token}"))
}

pub fn normalize_token_symbol(symbol: &str) -> Result<String> {
    let token = symbol.trim().to_ascii_uppercase();
    if token.is_empty() {
        return Err(anyhow!("token symbol is required"));
    }
    if token == "ANET" {
        return Err(anyhow!("token symbol ANET is reserved"));
    }
    if token.len() > 16 {
        return Err(anyhow!("token symbol must be 16 characters or fewer"));
    }
    if !token
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        return Err(anyhow!("token symbol may contain only A-Z, 0-9, _ or -"));
    }
    Ok(token)
}

pub fn validate_fee_bps(fee_bps: u16) -> Result<u16> {
    if fee_bps > MAX_FEE_BPS {
        return Err(anyhow!("fee_bps must be <= {MAX_FEE_BPS}"));
    }
    Ok(fee_bps)
}

pub fn initial_lp_units(anet_reserve_ants: u128, token_reserve_units: u128) -> Result<u128> {
    if anet_reserve_ants == 0 || token_reserve_units == 0 {
        return Err(anyhow!(
            "initial liquidity amounts must be greater than zero"
        ));
    }
    let product = anet_reserve_ants
        .checked_mul(token_reserve_units)
        .ok_or_else(|| anyhow!("liquidity product overflowed"))?;
    let units = integer_sqrt(product);
    if units == 0 {
        return Err(anyhow!("initial LP units would be zero"));
    }
    Ok(units)
}

pub fn quote_amount_out(
    reserve_in: u128,
    reserve_out: u128,
    amount_in: u128,
    fee_bps: u16,
) -> Result<(u128, u128, u64)> {
    if reserve_in == 0 || reserve_out == 0 {
        return Err(anyhow!("pool has no liquidity"));
    }
    if amount_in == 0 {
        return Err(anyhow!("swap amount must be greater than zero"));
    }

    let fee_den = 10_000_u128;
    let fee_num = u128::from(validate_fee_bps(fee_bps)?);

    let amount_in_after_fee = amount_in
        .checked_mul(
            fee_den
                .checked_sub(fee_num)
                .ok_or_else(|| anyhow!("invalid fee"))?,
        )
        .ok_or_else(|| anyhow!("swap amount overflowed"))?
        / fee_den;

    if amount_in_after_fee == 0 {
        return Err(anyhow!("swap amount is too small after fee"));
    }

    let fee_paid = amount_in
        .checked_sub(amount_in_after_fee)
        .ok_or_else(|| anyhow!("swap fee underflowed"))?;

    let numerator = reserve_out
        .checked_mul(amount_in_after_fee)
        .ok_or_else(|| anyhow!("swap numerator overflowed"))?;
    let denominator = reserve_in
        .checked_add(amount_in_after_fee)
        .ok_or_else(|| anyhow!("swap denominator overflowed"))?;

    let amount_out = numerator / denominator;
    if amount_out == 0 {
        return Err(anyhow!("swap output is too small"));
    }

    let spot = reserve_out as f64 / reserve_in as f64;
    let execution = amount_out as f64 / amount_in_after_fee as f64;
    let impact = if spot <= 0.0 || execution >= spot {
        0.0
    } else {
        ((spot - execution) / spot) * 10_000.0
    };

    Ok((amount_out, fee_paid, impact.max(0.0).round() as u64))
}

pub fn format_anet_fixed_u128(ants: u128) -> String {
    let whole = ants / 100_000_000_u128;
    let fractional = ants % 100_000_000_u128;
    format!("{whole}.{fractional:08}")
}

fn spot_token_units_per_anet(anet_reserve_ants: u128, token_reserve_units: u128) -> u128 {
    if anet_reserve_ants == 0 || token_reserve_units == 0 {
        return 0;
    }
    token_reserve_units
        .saturating_mul(100_000_000_u128)
        .checked_div(anet_reserve_ants)
        .unwrap_or(0)
}

fn spot_anet_ants_per_token_unit(anet_reserve_ants: u128, token_reserve_units: u128) -> u128 {
    if anet_reserve_ants == 0 || token_reserve_units == 0 {
        return 0;
    }
    anet_reserve_ants.checked_div(token_reserve_units).unwrap_or(0)
}

fn integer_sqrt(value: u128) -> u128 {
    if value <= 1 {
        return value;
    }

    let mut x0 = value;
    let mut x1 = (x0 + value / x0) / 2;
    while x1 < x0 {
        x0 = x1;
        x1 = (x0 + value / x0) / 2;
    }
    x0
}
