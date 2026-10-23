use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anrc20Token {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub owner: String,
    pub mintable: bool,
    #[serde(default)]
    pub balances: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Anrc20TokenView {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub total_supply_units: String,
    pub owner: String,
    pub mintable: bool,
    pub holders: usize,
}

impl Anrc20Token {
    pub fn view(&self) -> Anrc20TokenView {
        Anrc20TokenView {
            symbol: self.symbol.clone(),
            name: self.name.clone(),
            decimals: self.decimals,
            total_supply: self.total_supply,
            total_supply_units: self.total_supply.to_string(),
            owner: self.owner.clone(),
            mintable: self.mintable,
            holders: self.balances.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::Anrc20Token;

    #[test]
    fn token_view_preserves_exact_u64_supply_units() {
        let token = Anrc20Token {
            symbol: "LARGE".to_owned(),
            name: "Large supply token".to_owned(),
            decimals: 8,
            total_supply: u64::MAX,
            owner: "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            mintable: false,
            balances: HashMap::new(),
        };

        assert_eq!(token.view().total_supply_units, u64::MAX.to_string());
    }
}
