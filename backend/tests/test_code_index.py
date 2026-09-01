from app.analysis.code_index import index_source_texts, index_sources

_SOURCE = """
package com.example.app;

import android.webkit.WebView;

public class LoginActivity extends BaseActivity implements Callback {
    private String token;

    public void login(String user, String pass) {
        doWork();
    }

    protected int score() {
        return 1;
    }
}
"""


def test_index_extracts_classes_methods_fields():
    index = index_source_texts([("com/example/app/LoginActivity.java", _SOURCE)])
    assert index.file_count == 1
    classes = [entity for entity in index.entities if entity["entity_type"] == "class"]
    methods = [entity for entity in index.entities if entity["entity_type"] == "method"]
    fields = [entity for entity in index.entities if entity["entity_type"] == "field"]

    assert classes[0]["class_name"] == "LoginActivity"
    assert classes[0]["package"] == "com.example.app"
    assert classes[0]["superclass"] == "BaseActivity"
    assert "Callback" in classes[0]["interfaces"]

    method_names = {method["name"] for method in methods}
    assert {"login", "score"} <= method_names
    assert any(field["name"] == "token" for field in fields)


def test_index_provides_sources_for_rule_scanning():
    index = index_source_texts([("A.java", "x")])
    assert index.sources == [("A.java", "x")]


def test_index_missing_directory_returns_empty(tmp_path):
    index = index_sources(tmp_path / "does-not-exist")
    assert index.file_count == 0
    assert index.entities == []
