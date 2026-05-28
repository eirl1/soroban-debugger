use soroban_sdk::{Env, Val};

pub struct StorageAssertions<'a> {
    _env: &'a Env,
}

impl<'a> StorageAssertions<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { _env: env 
    }

    pub fn assert_has_key(&self, _contract_id: &str, key: Val) {
        // In a real implementation, we'd look up the contract and check its storage.
        // For now, let's just check the instance storage of the current env context
        // if it were a single contract test.
        assert!(self._env.storage().instance().has(&key));
    }

    pub fn assert_value_eq(&self, _contract_id: &str, key: Val, expected: Val) {
        let actual: Val = self._env.storage().instance().get(&key).unwrap();
        // Compare raw payloads since Val might not implement PartialEq in this version
        assert_eq!(actual.get_payload(), expected.get_payload());
    }
}//
//