//! EUI-48 address format
use core::str::FromStr;
use core::fmt;

// is also called mac address
/// EUI-48 Address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Eui48(pub [u8; 6]);

impl Eui48 {
    pub fn from_bytes(src: &[u8]) -> Self {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(src);
        Self(bytes)
    }
}

// allowed format: 00-11-22-33-44-55 or 00:11:22:33:44:55
impl FromStr for Eui48 {
    type Err = Eui48ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ans = [0u8; 6];
        let mut tmp = 0;
        let mut part_idx = 0;
        let mut total_idx = 0;
        let mut sep = false;
        let mut iter = s.chars();
        loop {
            let ch = iter.next();
            match ch {
                Some(ch @ ('0' ..= '9' | 'a' ..= 'f' | 'A' ..= 'F')) if !sep => {
                    let digit = match ch {
                        '0' ..= '9' => ch as u8 - b'0',
                        'a' ..= 'f' => ch as u8 - b'a' + 10,
                        'A' ..= 'F' => ch as u8 - b'A' + 10,
                        _ => unreachable!(),
                    };
                    tmp <<= 4;
                    tmp |= digit;
                    part_idx += 1;
                    if part_idx >= 2 {
                        sep = true;
                    }
                },
                Some(':' | '-') if sep && total_idx < 6 => {
                    ans[total_idx] = tmp;
                    tmp = 0;
                    total_idx += 1;
                    part_idx = 0;
                    sep = false;
                },
                None if total_idx == 5 && sep => {
                    ans[total_idx] = tmp;
                    return Ok(Eui48(ans))
                }
                _ => return Err(Eui48ParseError(()))
            }
        }
    }
}

impl fmt::Display for Eui48 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.0;
        write!(f, "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}", p[0], p[1], p[2], p[3], p[4], p[5])
    }
}

/// EUI-48 address parse error
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Eui48ParseError(());

#[cfg(test)]
mod test {
    use super::Eui48;
    #[test]
    fn eui48_parse() {
        assert_eq!("00-01-02-03-04-05".parse(), Ok(Eui48([0, 1, 2, 3, 4, 5])));
        assert_eq!("1a-b2-3C-D4-50-06".parse(), Ok(Eui48([0x1a, 0xb2, 0x3c, 0xd4, 0x50, 0x06])));
        assert!("1a-b2-3C-D4-50-".parse::<Eui48>().is_err());
        assert!("1a-b2-3C-D4-50-06-07".parse::<Eui48>().is_err());
        assert!("1a-b2-3G-D4-50-06".parse::<Eui48>().is_err());
        assert!("1a-b2-3G-D4-50-6".parse::<Eui48>().is_err());
    }
}
