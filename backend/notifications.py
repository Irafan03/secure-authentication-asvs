"""
notifications.py — Service de notification sécurisé pour ASVS 5.0.0 V6.3
Conforme aux exigences ASVS 6.3.5 (tentatives suspectes) et 6.3.7 (mise à jour des identifiants).

Ce module fournit :
- Une interface abstraite `BaseNotificationService`
- Une implémentation de production `EmailNotificationService` (SMTP/STARTTLS)
- Une implémentation de développement/journalisation `DevLogNotificationService`
- Des méthodes de haut niveau pour chaque événement de sécurité
- Aucune donnée sensible (mot de passe, secret TOTP) n'est jamais transmise
- L'échec d'envoi n'interrompt JAMAIS le flux d'authentification ou d'opération (fail-open sécurisé avec journalisation)
"""

import os
import logging
import smtplib
from abc import ABC, abstractmethod
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class BaseNotificationService(ABC):
    """Interface de base pour les services de notification de sécurité."""

    @abstractmethod
    def send_notification(self, recipient: str, subject: str, message: str, event_type: str) -> bool:
        """
        Envoie une notification de sécurité à un destinataire.
        
        Args:
            recipient: Adresse email de destination
            subject: Objet du message
            message: Contenu textuel de la notification
            event_type: Type d'événement (ex: 'new_device', 'credential_change')
            
        Returns:
            True si la notification a été traitée avec succès, False sinon
        """
        pass

    def notify_new_device(self, recipient: str, username: str, ip_address: str, user_agent: Optional[str] = None) -> bool:
        """ASVS 6.3.5: Notification lors d'une connexion depuis un nouvel appareil ou une nouvelle adresse IP."""
        subject = "[Sécurité] Nouvelle connexion détectée sur votre compte"
        body = (
            f"Bonjour {username},\n\n"
            f"Une connexion à votre compte a été détectée depuis une nouvelle adresse IP ou un nouvel appareil :\n"
            f"- Date / Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- Adresse IP : {ip_address}\n"
            f"- Navigateur / Appareil : {user_agent or 'Inconnu'}\n\n"
            f"Si vous êtes à l'origine de cette action, vous pouvez ignorer cet e-mail.\n"
            f"Si ce n'est pas vous, nous vous conseillons de changer immédiatement votre mot de passe."
        )
        return self.send_notification(recipient, subject, body, "suspicious_new_device")

    def notify_login_after_failures(self, recipient: str, username: str, ip_address: str, failed_count: int) -> bool:
        """ASVS 6.3.5: Notification lors d'une connexion réussie après plusieurs échecs consécutifs."""
        subject = "[Sécurité] Connexion réussie après plusieurs échecs"
        body = (
            f"Bonjour {username},\n\n"
            f"Une connexion à votre compte vient de réussir après {failed_count} tentatives infructueuses :\n"
            f"- Date / Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- Adresse IP : {ip_address}\n\n"
            f"Si vous n'êtes pas à l'origine de ces tentatives, veuillez modifier votre mot de passe immédiatement."
        )
        return self.send_notification(recipient, subject, body, "login_after_failures")

    def notify_partial_auth_failure(self, recipient: str, username: str, ip_address: str) -> bool:
        """ASVS 6.3.5: Notification lorsqu'une authentification a partiellement réussi (bon mot de passe, mais MFA échoué)."""
        subject = "[Sécurité] Alerte : Échec du second facteur d'authentification"
        body = (
            f"Bonjour {username},\n\n"
            f"Une tentative de connexion a présenté le mot de passe valide de votre compte, "
            f"mais a échoué à l'étape du second facteur (code MFA TOTP ou code de récupération invalide) :\n"
            f"- Date / Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- Adresse IP : {ip_address}\n\n"
            f"IMPORTANT : Votre mot de passe est probablement compromis. "
            f"Bien que le second facteur ait protégé votre compte, changez sans tarder votre mot de passe."
        )
        return self.send_notification(recipient, subject, body, "partial_auth_failure")

    def notify_inactive_login(self, recipient: str, username: str, ip_address: str, last_login_date: Optional[datetime] = None) -> bool:
        """ASVS 6.3.5: Notification lors d'une reconnexion après une longue période d'inactivité."""
        last_date_str = last_login_date.strftime('%Y-%m-%d %H:%M:%S') if last_login_date else "une longue période"
        subject = "[Sécurité] Reconnexion après inactivité prolongée"
        body = (
            f"Bonjour {username},\n\n"
            f"Une connexion à votre compte a eu lieu après une période d'inactivité (dernière session : {last_date_str}) :\n"
            f"- Date / Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- Adresse IP : {ip_address}\n\n"
            f"Si vous n'êtes pas à l'origine de cette connexion, veuillez contacter le support ou changer votre mot de passe."
        )
        return self.send_notification(recipient, subject, body, "inactive_login")

    def notify_password_changed(self, recipient: str, username: str, ip_address: str) -> bool:
        """ASVS 6.3.7: Notification après modification du mot de passe (sans mot de passe dans le corps)."""
        subject = "[Sécurité] Votre mot de passe a été modifié"
        body = (
            f"Bonjour {username},\n\n"
            f"Le mot de passe associé à votre compte a été modifié avec succès :\n"
            f"- Date / Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- Adresse IP : {ip_address}\n\n"
            f"Pour des raisons de sécurité, votre mot de passe n'est jamais transmis par e-mail.\n"
            f"Si vous n'avez pas demandé ce changement, contactez immédiatement l'administrateur de sécurité."
        )
        return self.send_notification(recipient, subject, body, "password_changed")

    def notify_password_reset(self, recipient: str, username: str, reset_url: str, initiated_by_admin: bool = False,
                              expires_in_minutes: int = 20) -> bool:
        subject = "[Sécurité] Réinitialisation du mot de passe"
        action = "Un administrateur a demandé" if initiated_by_admin else "Vous avez demandé"
        body = (f"Bonjour {username},\n\n{action} la réinitialisation de votre mot de passe. "
                f"Utilisez ce lien à usage unique, valable {expires_in_minutes} minutes :\n{reset_url}\n\n"
                "Si vous n'êtes pas à l'origine de cette demande, ignorez ce message et contactez le support.")
        return self.send_notification(recipient, subject, body, "password_reset_requested")

    def notify_mfa_recovery(self, recipient: str, username: str, recovery_url: str) -> bool:
        body = (f"Bonjour {username},\n\nUne demande de récupération MFA a été faite. "
                f"Confirmez-la avec votre mot de passe actuel via ce lien à usage unique :\n{recovery_url}")
        return self.send_notification(recipient, "[Sécurité] Récupération MFA", body, "mfa_recovery_requested")

    def notify_mfa_reset(self, recipient: str, username: str) -> bool:
        return self.send_notification(recipient, "[Sécurité] Facteur MFA réinitialisé",
            f"Le facteur MFA de votre compte {username} a été réinitialisé. Vous devrez réenrôler un facteur.", "mfa_reset")

    def notify_email_changed(self, old_email: str, new_email: str, username: str, ip_address: str) -> bool:
        """ASVS 6.3.7: Notification après changement d'adresse e-mail (envoyée à l'ancienne ET à la nouvelle adresse)."""
        subject = "[Sécurité] Changement de votre adresse e-mail"
        body_old = (
            f"Bonjour {username},\n\n"
            f"Une modification de l'adresse e-mail associée à votre compte a été effectuée :\n"
            f"- Ancienne adresse : {old_email}\n"
            f"- Nouvelle adresse : {new_email}\n"
            f"- Date / Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- Adresse IP : {ip_address}\n\n"
            f"Si vous n'êtes pas à l'origine de cette modification, intervenez immédiatement auprès du support."
        )
        body_new = (
            f"Bonjour {username},\n\n"
            f"Cette adresse e-mail ({new_email}) a été configurée comme adresse principale de votre compte.\n"
            f"- Date / Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- Adresse IP : {ip_address}\n\n"
            f"Si vous n'avez pas effectué cette démarche, contactez immédiatement le support de sécurité."
        )
        res_old = self.send_notification(old_email, subject, body_old, "email_changed_old")
        res_new = self.send_notification(new_email, subject, body_new, "email_changed_new")
        return res_old and res_new

    def notify_username_changed(self, recipient: str, old_username: str, new_username: str, ip_address: str) -> bool:
        """ASVS 6.3.7: Notification après modification du nom d'utilisateur."""
        subject = "[Sécurité] Votre nom d'utilisateur a été mis à jour"
        body = (
            f"Bonjour,\n\n"
            f"Le nom d'utilisateur de votre compte est passé de '{old_username}' à '{new_username}' :\n"
            f"- Date / Heure : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"- Adresse IP : {ip_address}\n\n"
            f"Si vous n'avez pas demandé cette modification, contactez le support de sécurité."
        )
        return self.send_notification(recipient, subject, body, "username_changed")


class DevLogNotificationService(BaseNotificationService):
    """
    Implémentation de notification pour environnement de développement / test.
    Journalise les alertes de sécurité dans les logs et garde un historique en mémoire.
    """

    def __init__(self):
        self.sent_notifications: List[Dict[str, Any]] = []

    def send_notification(self, recipient: str, subject: str, message: str, event_type: str) -> bool:
        record = {
            "recipient": recipient,
            "subject": subject,
            "message": message,
            "event_type": event_type,
            "sent_at": datetime.now()
        }
        self.sent_notifications.append(record)
        logger.warning(
            f"[SECURITY NOTIFICATION DEV] To: {recipient} | Type: {event_type} | Subject: {subject}\n"
            f"--- Contenu ---\n{message}\n----------------"
        )
        return True

    def clear(self):
        """Réinitialise l'historique des notifications (utile pour les tests)."""
        self.sent_notifications.clear()


class EmailNotificationService(BaseNotificationService):
    """
    Implémentation de notification par e-mail en production via SMTP.
    Paramètres configurables via variables d'environnement.
    """

    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        use_tls: bool = True,
        use_ssl: bool = False,
        from_email: Optional[str] = None
    ):
        self.smtp_host = smtp_host or os.environ.get("SMTP_HOST", "localhost")
        self.smtp_port = smtp_port or int(os.environ.get("SMTP_PORT", 587))
        self.smtp_user = smtp_user or os.environ.get("SMTP_USER", "")
        self.smtp_password = smtp_password or os.environ.get("SMTP_PASSWORD", "")
        self.use_tls = use_tls if use_tls is not None else (os.environ.get("SMTP_USE_TLS", "true").lower() == "true")
        self.use_ssl = use_ssl if use_ssl is not None else (os.environ.get("SMTP_USE_SSL", "false").lower() == "true")
        self.from_email = from_email or os.environ.get("NOTIFICATION_EMAIL_FROM", "security@secureauth.local")

    def send_notification(self, recipient: str, subject: str, message: str, event_type: str) -> bool:
        if not self.smtp_host:
            logger.warning("SMTP non configuré : notification annulée pour %s", recipient)
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = recipient
            msg["Subject"] = subject
            msg["X-Security-Event"] = event_type
            msg.attach(MIMEText(message, "plain", "utf-8"))

            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)

            with server:
                if self.use_tls and not self.use_ssl:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            logger.info("Notification de sécurité transmise avec succès à %s (%s)", recipient, event_type)
            return True
        except Exception as exc:
            # Ne jamais bloquer l'authentification si le serveur SMTP est en panne
            logger.error("Échec d'envoi de la notification de sécurité à %s : %s", recipient, exc)
            return False


# Singleton et gestion de la fabrique
_current_notification_service: Optional[BaseNotificationService] = None


def get_notification_service() -> BaseNotificationService:
    """Retourne l'instance active du service de notification."""
    global _current_notification_service
    if _current_notification_service is None:
        backend = os.environ.get("NOTIFICATION_BACKEND", "dev").lower()
        if backend == "email" and os.environ.get("SMTP_HOST"):
            _current_notification_service = EmailNotificationService()
        else:
            _current_notification_service = DevLogNotificationService()
    return _current_notification_service


def set_notification_service(service: BaseNotificationService) -> None:
    """Permet d'injecter une implémentation (ex: mock dans les tests)."""
    global _current_notification_service
    _current_notification_service = service
