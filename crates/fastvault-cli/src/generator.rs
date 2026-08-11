use rand::seq::SliceRandom;
use rand::Rng;

pub struct SecretGenerator;

impl SecretGenerator {
    pub fn generate_password(length: usize, no_symbols: bool) -> String {
        let lowercase = b"abcdefghijklmnopqrstuvwxyz";
        let uppercase = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let digits = b"0123456789";
        let symbols = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

        let mut charset = Vec::new();
        charset.extend_from_slice(lowercase);
        charset.extend_from_slice(uppercase);
        charset.extend_from_slice(digits);
        if !no_symbols {
            charset.extend_from_slice(symbols);
        }

        let mut rng = rand::thread_rng();
        let mut password = Vec::with_capacity(length);

        password.push(*lowercase.choose(&mut rng).unwrap());
        password.push(*uppercase.choose(&mut rng).unwrap());
        password.push(*digits.choose(&mut rng).unwrap());
        if !no_symbols {
            password.push(*symbols.choose(&mut rng).unwrap());
        }

        while password.len() < length {
            password.push(*charset.choose(&mut rng).unwrap());
        }

        password.shuffle(&mut rng);
        String::from_utf8(password).unwrap()
    }

    pub fn generate_token(length: usize) -> String {
        let mut bytes = vec![0u8; length];
        rand::thread_rng().fill(&mut bytes[..]);
        hex::encode(bytes)
    }
}
