from __future__ import annotations

from correlation.records import EndpointRecord, ParameterRecord, endpoint_key
from recon import correlation


def test_identical_identities_different_evidence_preserve_originals():
    e1 = EndpointRecord(method='GET', pattern='/api/x', host='example.com', evidence_id='e1')
    e2 = EndpointRecord(method='GET', pattern='/api/x', host='example.com', evidence_id='e2')
    p = ParameterRecord(endpoint_key=endpoint_key('GET','/api/x','example.com'), name='id', location='query', significance='medium', evidence_id='e3')
    g = correlation.correlate_endpoints([e2, e1], [p])
    assert len(g) == 1
    assert g[0].evidence_ids == ('e1', 'e2', 'e3')
    assert id(g[0].endpoints[0]) in (id(e1), id(e2))
    assert id(g[0].endpoints[1]) in (id(e1), id(e2))
    assert g[0].endpoints[0] is not g[0].endpoints[1]


def test_different_host_method_pattern_separate():
    e1 = EndpointRecord(method='GET', pattern='/a', host='a.com', evidence_id='e1')
    e2 = EndpointRecord(method='POST', pattern='/a', host='a.com', evidence_id='e2')
    e3 = EndpointRecord(method='GET', pattern='/a', host='b.com', evidence_id='e3')
    e4 = EndpointRecord(method='GET', pattern='/b', host='a.com', evidence_id='e4')
    g = correlation.correlate_endpoints([e1,e2,e3,e4])
    assert len(g) == 4


def test_parameters_attach_only_exact_match():
    ek1 = endpoint_key('GET', '/x', 'h1')
    ek2 = endpoint_key('GET', '/x', 'h2')
    e1 = EndpointRecord(method='GET', pattern='/x', host='h1', evidence_id='e1')
    e2 = EndpointRecord(method='GET', pattern='/x', host='h2', evidence_id='e2')
    p1 = ParameterRecord(endpoint_key=ek1, name='q', location='query', significance='low', evidence_id='p1')
    p2 = ParameterRecord(endpoint_key=ek2, name='q', location='query', significance='low', evidence_id='p2')
    g = correlation.correlate_endpoints([e1,e2], [p1,p2])
    assert len(g) == 2


def test_orphan_parameters_no_group_no_attach():
    e1 = EndpointRecord(method='GET', pattern='/x', host='h1', evidence_id='e1')
    p_orphan = ParameterRecord(endpoint_key=endpoint_key('GET','/y','h1'), name='q', location='query', significance='low', evidence_id='po')
    g = correlation.correlate_endpoints([e1], [p_orphan])
    assert len(g) == 1
    assert len(g[0].parameters) == 0


def test_evidence_sorted_deduped():
    ek = endpoint_key('GET', '/x', 'h')
    e1 = EndpointRecord(method='GET', pattern='/x', host='h', evidence_id='e2')
    e2 = EndpointRecord(method='GET', pattern='/x', host='h', evidence_id='e1')
    p = ParameterRecord(endpoint_key=ek, name='q', location='query', significance='low', evidence_id='e1')
    g = correlation.correlate_endpoints([e1,e2], [p])
    assert g[0].evidence_ids == ('e1','e2')


def test_deterministic_under_shuffle():
    e1 = EndpointRecord(method='GET', pattern='/x', host='h', evidence_id='e1')
    e2 = EndpointRecord(method='GET', pattern='/x', host='h', evidence_id='e2')
    p1 = ParameterRecord(endpoint_key=endpoint_key('GET','/x','h'), name='b', location='query', significance='low', evidence_id='p1')
    p2 = ParameterRecord(endpoint_key=endpoint_key('GET','/x','h'), name='a', location='header', significance='low', evidence_id='p2')
    g1 = correlation.correlate_endpoints([e2,e1], [p2,p1])
    g2 = correlation.correlate_endpoints([e1,e2], [p1,p2])
    assert g1 == g2
    assert g1[0].parameters[0].name == 'a'


def test_inputs_not_mutated():
    e1 = EndpointRecord(method='GET', pattern='/x', host='h', evidence_id='e1')
    lst = [e1]
    g = correlation.correlate_endpoints(lst)
    assert lst == [e1]
    assert g[0].endpoints[0] is e1


def test_missing_or_malformed_skipped():
    class Bad:
        pass
    g = correlation.correlate_endpoints([Bad()], None)
    assert g == ()


def test_duplicate_endpoint_observations_preserved():
    e1 = EndpointRecord(method='GET', pattern='/dup', host='h', evidence_id='e1')
    e2 = EndpointRecord(method='GET', pattern='/dup', host='h', evidence_id='e1')
    g = correlation.correlate_endpoints([e2, e1])
    assert len(g) == 1
    assert len(g[0].endpoints) == 2
    assert g[0].evidence_ids == ('e1',)


def test_duplicate_parameter_observations_preserved():
    ek = endpoint_key('GET', '/dup', 'h')
    e1 = EndpointRecord(method='GET', pattern='/dup', host='h', evidence_id='e1')
    p1 = ParameterRecord(endpoint_key=ek, name='q', location='query', significance='low', evidence_id='p1')
    p2 = ParameterRecord(endpoint_key=ek, name='q', location='query', significance='low', evidence_id='p1')
    g = correlation.correlate_endpoints([e1], [p1, p2])
    assert len(g) == 1
    assert len(g[0].parameters) == 2
    assert g[0].evidence_ids == ('e1', 'p1')


def test_mixed_input_attaches_parameters():
    ek = endpoint_key('GET', '/mixed', 'h')
    e = EndpointRecord(method='GET', pattern='/mixed', host='h', evidence_id='e1')
    p = ParameterRecord(endpoint_key=ek, name='q', location='query', significance='low', evidence_id='p1')
    g = correlation.correlate_endpoints([e, p])
    assert len(g) == 1
    assert [c.name for c in g[0].parameters] == ['q']
    assert g[0].evidence_ids == ('e1', 'p1')


def test_explicit_parameters_take_precedence_over_mixed_input():
    ek = endpoint_key('GET', '/mixed', 'h')
    e = EndpointRecord(method='GET', pattern='/mixed', host='h', evidence_id='e1')
    p_implicit = ParameterRecord(endpoint_key=ek, name='implicit', location='query', significance='low', evidence_id='pi')
    p_explicit = ParameterRecord(endpoint_key=ek, name='explicit', location='query', significance='low', evidence_id='pe')
    g = correlation.correlate_endpoints([e, p_implicit], [p_explicit])
    assert [c.name for c in g[0].parameters] == ['explicit']
    assert g[0].evidence_ids == ('e1', 'pe')


def test_explicit_empty_parameters_suppresses_mixed_extraction():
    ek = endpoint_key('GET', '/mixed', 'h')
    e = EndpointRecord(method='GET', pattern='/mixed', host='h', evidence_id='e1')
    p = ParameterRecord(endpoint_key=ek, name='q', location='query', significance='low', evidence_id='p1')
    g = correlation.correlate_endpoints([e, p], [])
    assert g[0].parameters == ()
    assert g[0].evidence_ids == ('e1',)


def test_generator_input_is_consumed_once():
    ek = endpoint_key('GET', '/gen', 'h')
    e = EndpointRecord(method='GET', pattern='/gen', host='h', evidence_id='e1')
    p = ParameterRecord(endpoint_key=ek, name='q', location='query', significance='low', evidence_id='p1')
    seen = []

    def source():
        for item in (e, p):
            seen.append(item)
            yield item

    g = correlation.correlate_endpoints(source())
    assert seen == [e, p]
    assert len(g[0].parameters) == 1
    assert g[0].evidence_ids == ('e1', 'p1')


def test_mixed_input_collection_not_mutated():
    ek = endpoint_key('GET', '/mixed', 'h')
    e = EndpointRecord(method='GET', pattern='/mixed', host='h', evidence_id='e1')
    p = ParameterRecord(endpoint_key=ek, name='q', location='query', significance='low', evidence_id='p1')
    items = [e, p]
    correlation.correlate_endpoints(items)
    assert items == [e, p]
    assert items[0] is e
    assert items[1] is p
