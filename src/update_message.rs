use trust_dns::{
    op::{Message, MessageType, OpCode, Query, UpdateMessage},
    rr::{DNSClass, Name, Record, RecordSet, RecordType},
};

// This code is taken from `update_message.rs` in the `trust_dns` crate, and
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
