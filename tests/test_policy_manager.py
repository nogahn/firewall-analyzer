import pytest
from datetime import datetime
from src.core.models import Connection, Policy, PolicyCondition, ConnectionField

@pytest.fixture
def manager():
    from src.services.policy_manager import PolicyManager
    return PolicyManager()

def make_policy(policy_id, conditions, action):
    return Policy(policy_id=policy_id, conditions=conditions, action=action)

def make_connection(**kwargs):
    defaults = {
        "connection_id": "c1",
        "source_ip": "1.1.1.1",
        "destination_ip": "2.2.2.2",
        "destination_port": 80,
        "protocol": "TCP",
        "timestamp": datetime.now(),
    }
    defaults.update(kwargs)
    return Connection(**defaults)

@pytest.mark.parametrize(
    "policy_conditions, conn_kwargs, expected_policy_id",
    [
        (
            [PolicyCondition(field=ConnectionField.SOURCE_IP, operator="==", value="1.2.3.4")],
            {"source_ip": "1.2.3.4"},
            "p1"
        ),
        (
            [PolicyCondition(field=ConnectionField.SOURCE_IP, operator="==", value="10.0.0.1")],
            {"source_ip": "1.1.1.1"},
            None
        ),
        (
            [
                PolicyCondition(field=ConnectionField.DESTINATION_PORT, operator="==", value=443),
                PolicyCondition(field=ConnectionField.PROTOCOL, operator="==", value="TCP"),
            ],
            {"destination_port": 443, "protocol": "TCP"},
            "p2"
        ),
        (
            [],
            {"source_ip": "any", "destination_ip": "any", "destination_port": 123, "protocol": "UDP"},
            "p3"
        ),
    ]
)
def test_policy_matching(manager, policy_conditions, conn_kwargs, expected_policy_id):
    policy_id = expected_policy_id or "temp_policy"
    policy = make_policy(policy_id=policy_id, conditions=policy_conditions, action="allow")
    manager.add_policy(policy)
    conn = make_connection(**conn_kwargs)
    matched = manager.get_matching_policy(conn)
    if expected_policy_id:
        assert matched is not None
        assert matched.policy_id == expected_policy_id
    else:
        assert matched is None

def test_first_matching_policy_is_returned(manager):
    p1 = make_policy("p3", [PolicyCondition(field=ConnectionField.DESTINATION_PORT, operator="==", value=443)], "allow")
    p2 = make_policy("p4", [PolicyCondition(field=ConnectionField.DESTINATION_PORT, operator="==", value=443)], "block")
    manager.add_policy(p1)
    manager.add_policy(p2)
    conn = make_connection(destination_port=443)
    matched = manager.get_matching_policy(conn)
    assert matched is not None
    assert matched.policy_id == "p3"

def test_multiple_conditions_all_must_match(manager):
    policy = make_policy(
        "p5",
        [
            PolicyCondition(field=ConnectionField.SOURCE_IP, operator="==", value="1.1.1.1"),
            PolicyCondition(field=ConnectionField.DESTINATION_PORT, operator="==", value=80),
        ],
        "block"
    )
    manager.add_policy(policy)
    conn = make_connection(source_ip="1.1.1.1", destination_port=80)
    matched = manager.get_matching_policy(conn)
    assert matched is not None
    assert matched.policy_id == "p5"

def test_policy_with_and_without_conditions_prioritizes_order(manager):
    policy1 = make_policy("p1", [PolicyCondition(field=ConnectionField.SOURCE_IP, operator="==", value="8.8.8.8")], "block")
    policy2 = make_policy("p2", [], "allow")
    manager.add_policy(policy1)
    manager.add_policy(policy2)
    conn = make_connection(source_ip="8.8.8.8", destination_port=123, protocol="UDP")
    matched = manager.get_matching_policy(conn)
    assert matched is not None
    assert matched.policy_id == "p1"

def test_connection_field_not_indexed_skipped_gracefully(manager):
    policy = make_policy("p8", [PolicyCondition(field=ConnectionField.DESTINATION_PORT, operator="==", value=443)], "block")
    manager.add_policy(policy)
    conn = make_connection(destination_port=444)
    matched = manager.get_matching_policy(conn)
    assert matched is None

def test_connection_with_unindexed_field_does_not_fail(manager):
    policy = make_policy("p8", [PolicyCondition(field=ConnectionField.SOURCE_IP, operator="==", value="1.2.3.4")], "allow")
    manager.add_policy(policy)
    conn = make_connection(source_ip="1.2.3.4", destination_ip="does.not.matter", destination_port=8080, protocol="HTTP")
    matched = manager.get_matching_policy(conn)
    assert matched is not None
    assert matched.policy_id == "p8"

def test_multiple_policies_some_match_some_not_match(manager):
    p1 = make_policy(
        "p9",
        [
            PolicyCondition(field=ConnectionField.DESTINATION_PORT, operator="==", value=443),
            PolicyCondition(field=ConnectionField.PROTOCOL, operator="==", value="UDP")
        ],
        "block"
    )
    p2 = make_policy(
        "p10",
        [
            PolicyCondition(field=ConnectionField.DESTINATION_PORT, operator="==", value=443),
            PolicyCondition(field=ConnectionField.PROTOCOL, operator="==", value="TCP")
        ],
        "allow"
    )
    manager.add_policy(p1)
    manager.add_policy(p2)
    conn = make_connection(destination_port=443, protocol="TCP")
    matched = manager.get_matching_policy(conn)
    assert matched is not None
    assert matched.policy_id == "p10"

def test_all_candidates_fail_in_full_match(manager):
    p1 = make_policy(
        "p11",
        [
            PolicyCondition(field=ConnectionField.DESTINATION_PORT, operator="==", value=443),
            PolicyCondition(field=ConnectionField.PROTOCOL, operator="==", value="UDP")
        ],
        "block"
    )
    p2 = make_policy(
        "p12",
        [PolicyCondition(field=ConnectionField.SOURCE_IP, operator="==", value="10.0.0.1")],
        "allow"
    )
    manager.add_policy(p1)
    manager.add_policy(p2)
    conn = make_connection(source_ip="11.0.0.1", destination_port=443, protocol="TCP")
    matched = manager.get_matching_policy(conn)
    assert matched is None

def test_two_policies_matches(manager):
    policies = [
        make_policy(
            "p13",
            [
                PolicyCondition(field=ConnectionField.DESTINATION_IP, operator="==", value="1.1.1.1"),
                PolicyCondition(field=ConnectionField.DESTINATION_PORT, operator="==", value=80),
                PolicyCondition(field=ConnectionField.PROTOCOL, operator="==", value="TCP")
            ],
            "block"
        ),
        make_policy(
            "p14",
            [PolicyCondition(field=ConnectionField.SOURCE_IP, operator="==", value="2.2.2.2")],
            "block"
        ),
    ]
    for policy in policies:
        manager.add_policy(policy)
    conn = make_connection(source_ip="2.2.2.2", destination_ip="1.1.1.1", destination_port=80, protocol="TCP")
    matched = manager.get_matching_policy(conn)
    assert matched is not None
    assert matched.policy_id == "p13"

def test_no_policies(manager):
    conn = make_connection(source_ip="2.2.2.2", destination_ip="1.1.1.1", destination_port=80, protocol="TCP")
    matched = manager.get_matching_policy(conn)
    assert matched is None

def test_adding_duplicate_policy_raises(manager):
    policy = make_policy("p100", [], "allow")
    manager.add_policy(policy)
    duplicate_policy = make_policy("p100", [], "block")
    with pytest.raises(ValueError) as excinfo:
        manager.add_policy(duplicate_policy)
    assert "already exists" in str(excinfo.value)
