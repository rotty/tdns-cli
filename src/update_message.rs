use hickory_client::{
    op::{Message, MessageType, OpCode, Query, UpdateMessage},
    rr::{DNSClass, Name, Record, RecordSet, RecordType},
};

// This code is taken from `update_message.rs` in the `hickory` crate, and
// adapted to omit EDNS.
pub fn create(rrset: RecordSet, zone_origin: Name) -> Message {
    // TODO: assert non-empty rrset?
    assert!(zone_origin.zone_of(rrset.name()));

    // for updates, the query section is used for the zone
    let mut zone = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(rrset.dns_class())
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    let mut prerequisite = Record::with(rrset.name().clone(), rrset.record_type(), 0);
    prerequisite.set_dns_class(DNSClass::NONE);
    message.add_pre_requisite(prerequisite);
    message.add_updates(rrset);
    message
}

pub fn append(rrset: RecordSet, zone_origin: Name, must_exist: bool) -> Message {
    assert!(zone_origin.zone_of(rrset.name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(rrset.dns_class())
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    if must_exist {
        let mut prerequisite = Record::with(rrset.name().clone(), rrset.record_type(), 0);
        prerequisite.set_dns_class(DNSClass::ANY);
        message.add_pre_requisite(prerequisite);
    }

    message.add_updates(rrset);

    message
}

pub fn delete_by_rdata(mut rrset: RecordSet, zone_origin: Name) -> Message {
    assert!(zone_origin.zone_of(rrset.name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(rrset.dns_class())
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    // the class must be none for delete
    rrset.set_dns_class(DNSClass::NONE);
    // the TTL should be 0
    rrset.set_ttl(0);
    message.add_updates(rrset);

    message
}

pub fn delete_rrset(mut record: Record, zone_origin: Name) -> Message {
    assert!(zone_origin.zone_of(record.name()));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(record.dns_class())
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    // the class must be none for an rrset delete
    record.set_dns_class(DNSClass::ANY);
    // the TTL should be 0
    record.set_ttl(0);
    // the rdata must be null to delete all rrsets
    record.set_data(None);
    message.add_update(record);

    message
}

pub fn delete_all(name_of_records: Name, zone_origin: Name, dns_class: DNSClass) -> Message {
    assert!(zone_origin.zone_of(&name_of_records));

    // for updates, the query section is used for the zone
    let mut zone: Query = Query::new();
    zone.set_name(zone_origin)
        .set_query_class(dns_class)
        .set_query_type(RecordType::SOA);

    // build the message
    let mut message: Message = Message::new();
    message
        .set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);
    message.add_zone(zone);

    // the TTL should be 0
    // the rdata must be null to delete all rrsets
    // the record type must be any
    let mut record = Record::with(name_of_records, RecordType::ANY, 0);

    // the class must be none for an rrset delete
    record.set_dns_class(DNSClass::ANY);

    message.add_update(record);

    message
}
