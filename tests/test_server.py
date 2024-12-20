import pytest
from src.server import create_app, LicenseManager
from src.server.models import License

@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_verify_license(client):
    # Test verify license API
    response = client.post('/verify', json={'api_key': 'test_key'})
    assert response.status_code in [200, 403]

def test_create_license(client):
    # Test create license API
    response = client.post('/license', json={'duration': 30})
    assert response.status_code == 200
    assert 'api_key' in response.json['data'] 