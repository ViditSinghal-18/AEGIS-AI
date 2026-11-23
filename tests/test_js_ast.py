import tempfile
from pathlib import Path
from ast_analyzer import evaluate_cve_function_reachability, analyze_source_tree

def test_js_reachability():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / 'package.json').write_text('{"dependencies": {"lodash": "^4.17.21", "tough-cookie": "^2.5.0"}}', encoding='utf-8')
        (p / 'app.js').write_text('''
const express = require('express');
const _ = require('lodash');
const { parse } = require('tough-cookie');
const app = express();

app.get('/test', (req, res) => {
    const rendered = _.template('hello');
    res.send(rendered);
});
''', encoding='utf-8')

        tree = analyze_source_tree(str(p))
        assert 'lodash' in tree['imported_packages']
        assert 'tough-cookie' in tree['imported_packages']

        # Lodash template is called -> reachable_function
        res1 = evaluate_cve_function_reachability('CVE-2021-23337', 'lodash', tree)
        assert res1['verdict'] == 'reachable_function'
        assert any('template' in s for s in res1['matched_symbols'])

        # tough-cookie parse is NOT called in code -> imported_only
        res2 = evaluate_cve_function_reachability('CVE-2023-26136', 'tough-cookie', tree)
        assert res2['verdict'] == 'imported_only'

        # Remote target without source -> unknown
        res3 = evaluate_cve_function_reachability('CVE-2021-23337', 'lodash', None)
        assert res3['verdict'] == 'unknown (no source provided)'

if __name__ == '__main__':
    test_js_reachability()
    print('ALL JS AST TESTS PASSED!')
