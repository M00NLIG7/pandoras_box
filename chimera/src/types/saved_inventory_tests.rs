use super::Host;
use serde_json::{json, Value};

fn legacy() -> Value {
    serde_json::from_str(include_str!("legacy_inventory.json")).unwrap()
}

#[test]
fn legacy_fields_round_trip_with_canonical_tags_and_unscaled_mib() {
    let mut expected = legacy();
    assert_eq!(expected.as_object().unwrap().len(), 14);
    let host: Host = serde_json::from_value(expected.clone()).unwrap();
    expected["shares"][0]["shareType"] = json!("NFS");
    expected["shares"][1]["shareType"] = json!("SMB");
    expected["sectionErrors"] = json!([]);
    assert_eq!(serde_json::to_value(host).unwrap(), expected);
}

#[test]
fn typed_diagnostics_preserve_messages_and_reject_invalid_data() {
    let mut value = legacy();
    value["shares"] = json!([]);
    for errors in [
        json!([]),
        json!([{"section":"services","message":" sample\nmessage "}]),
    ] {
        value["sectionErrors"] = errors;
        let host: Host = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(host).unwrap(), value);
    }
    value["sectionErrors"] = Value::Null;
    assert!(serde_json::from_value::<Host>(value.clone()).is_err());
    value["sectionErrors"] = json!([]);
    value["shares"] = json!([{"shareType":"other","networkPath":"/invalid"}]);
    assert!(serde_json::from_value::<Host>(value).is_err());
}
