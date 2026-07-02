from fastapi.testclient import TestClient
from api.server import app

# test de création d'un nouvel utilisateur
def test_register_user():
    client = TestClient(app)
    response = client.post(
        "/siem/api/register/",
        json={
            "username": "Hubert Maximus",
            "email": "hubert@example.com", 
            "password": "Hubert@1234",
            "role": 1,
            }
    )
    assert response.status_code == 201

# test de récupération des utilisateur dans la base de données


# test de modification du mot de passe de la base de données

# test de suppression d'un nouvel utilisateur