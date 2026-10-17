"""
create_admin.py — Commande d'installation dédiée pour créer un compte administrateur
ASVS 5.0.0 V6.3.2 (Niveau 2)

Conformité ASVS 6.3.2:
- Aucun compte ni mot de passe par défaut n'est codé en dur dans le projet.
- La création de l'administrateur initial s'effectue via cette commande interactive ou CLI.
- Le mot de passe est saisi par l'opérateur et strictement validé par `validate_password` (ASVS 6.2).
"""

import sys
import argparse
import getpass
import logging
from .auth_register import validate_password, validate_username, validate_email_address, hash_password
from .models import get_db_session, User, init_db_orm

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


def create_admin(username: str, email: str, password: str) -> bool:
    """
    Crée un compte administrateur initial en base de données via SQLAlchemy ORM.
    
    Args:
        username: Nom d'utilisateur de l'administrateur
        email: Adresse e-mail de l'administrateur
        password: Mot de passe saisi par l'opérateur
        
    Returns:
        True si le compte a été créé avec succès, False sinon
    """
    # 1. Validation du nom d'utilisateur
    u_res = validate_username(username)
    if not u_res["valid"]:
        for err in u_res["errors"]:
            print(f"[ERREUR] Nom d'utilisateur invalide : {err}", file=sys.stderr)
        return False

    # 2. Validation de l'adresse email
    e_res = validate_email_address(email)
    if not e_res["valid"]:
        for err in e_res["errors"]:
            print(f"[ERREUR] Adresse email invalide : {err}", file=sys.stderr)
        return False
    normalized_email = e_res["normalized"]

    # 3. Validation stricte du mot de passe (ASVS 6.2)
    p_res = validate_password(password, username)
    if not p_res["valid"]:
        print("[ERREUR] Le mot de passe ne respecte pas les critères de sécurité ASVS :", file=sys.stderr)
        for err in p_res["errors"]:
            print(f"  • {err}", file=sys.stderr)
        return False

    # 4. Hachage sécurisé Argon2id
    password_hash = hash_password(password)

    # 5. Création via ORM
    session = get_db_session()
    try:
        # Vérifier unicité
        existing = session.query(User).filter(
            (User.username == username) | (User.email == normalized_email)
        ).first()
        if existing:
            print("[ERREUR] Un utilisateur avec ce nom ou cette adresse email existe déjà.", file=sys.stderr)
            return False

        admin_user = User(
            username=username,
            email=normalized_email,
            password_hash=password_hash,
            role='admin',
            is_active=True,
            mfa_enabled=False
        )
        session.add(admin_user)
        session.commit()
        print(f"[SUCCÈS] Compte administrateur '{username}' créé avec succès (ID: {admin_user.id}).")
        return True
    except Exception as exc:
        session.rollback()
        print(f"[ERREUR] Impossible de créer l'administrateur : {exc}", file=sys.stderr)
        return False
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser(description="Commande d'installation de compte administrateur initial (ASVS 6.3.2)")
    parser.add_argument("--username", help="Nom d'utilisateur administrateur")
    parser.add_argument("--email", help="Adresse e-mail administrateur")
    parser.add_argument("--password", help="Mot de passe administrateur (si omis, sera demandé de manière masquée)")

    args = parser.parse_args()

    # Initialisation des tables si nécessaire
    init_db_orm()

    username = args.username
    if not username:
        username = input("Nom d'utilisateur administrateur : ").strip()

    email = args.email
    if not email:
        email = input("Adresse e-mail administrateur : ").strip()

    password = args.password
    if not password:
        password = getpass.getpass("Mot de passe administrateur (min 12 car.) : ")
        password_confirm = getpass.getpass("Confirmation du mot de passe : ")
        if password != password_confirm:
            print("[ERREUR] Les deux mots de passe saisis ne correspondent pas.", file=sys.stderr)
            sys.exit(1)

    success = create_admin(username, email, password)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
