//! Stream JSON while bounding the materialized tree. Omitted values remain in
//! the raw artifact and the caller must withhold complete coverage.

use serde::Deserialize;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;
use std::io::Read;

pub(super) struct Budget {
    remaining: usize,
    pub omitted: bool,
}

impl Budget {
    pub fn new(bytes: usize) -> Self {
        Self {
            remaining: bytes,
            omitted: false,
        }
    }

    fn reserve(&mut self, bytes: usize) -> bool {
        if bytes > self.remaining {
            self.omitted = true;
            false
        } else {
            self.remaining -= bytes;
            true
        }
    }
}

pub(super) fn read(reader: impl Read, budget: &mut Budget) -> serde_json::Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let value = Node { budget, depth: 0 }.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct Node<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Node<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth >= 64 || !self.budget.reserve(64) {
            self.budget.omitted = true;
            IgnoredAny::deserialize(deserializer)?;
            return Ok(Value::Null);
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Node<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        Ok(Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or(Value::Null))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        // Do not replace an identifier/evidence string with a truncated one.
        if value.len() > 1024 * 1024 || !self.budget.reserve(value.len()) {
            self.budget.omitted = true;
            Ok(Value::Null)
        } else {
            Ok(Value::String(value.to_owned()))
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while values.len() < 100_000 && self.budget.remaining >= 64 {
            let next = sequence.next_element_seed(Node {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
            let Some(value) = next else {
                return Ok(Value::Array(values));
            };
            values.push(value);
        }
        // IgnoredAny validates skipped bytes without constructing their tree.
        while sequence.next_element::<IgnoredAny>()?.is_some() {
            self.budget.omitted = true;
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 512 || !self.budget.reserve(key.len() + 64) {
                self.budget.omitted = true;
                // JSON uses the last duplicate key. Keeping an earlier
                // verdict when its replacement is omitted would change it.
                values.remove(&key);
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            let value = map.next_value_seed(Node {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_string_is_omitted_without_consuming_the_budget_for_later_findings() {
        let bytes = format!(
            r#"{{"padding":"{}","results":[{{"check_id":"real-rule"}}]}}"#,
            "x".repeat(1024 * 1024 + 1)
        );
        let mut budget = Budget::new(2048);
        let value = read(bytes.as_bytes(), &mut budget).unwrap();
        assert!(budget.omitted);
        assert_eq!(value["padding"], Value::Null);
        assert_eq!(value["results"][0]["check_id"], "real-rule");
    }

    #[test]
    fn omitted_duplicate_key_does_not_restore_an_earlier_verdict() {
        let value = read(
            br#"{"status":"failed","padding":[1,2,3],"status":"passed"}"#.as_slice(),
            &mut Budget::new(512),
        )
        .unwrap();
        assert!(!value.as_object().unwrap().contains_key("status"));
    }

    #[test]
    fn skipped_suffix_still_requires_valid_json_and_no_trailing_document() {
        for bytes in [b"[1,2,3,invalid]".as_slice(), b"[1,2,3] {}".as_slice()] {
            assert!(read(bytes, &mut Budget::new(128)).is_err());
        }
        let value = read(b"[1,2,3]".as_slice(), &mut Budget::new(128)).unwrap();
        assert_eq!(value, serde_json::json!([1]));
    }
}
