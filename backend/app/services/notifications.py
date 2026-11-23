"""In-app notifications. Nothing is ever sent outside the application by default."""

from sqlalchemy.orm import Session

from app.models import Notification, Role, User


def notify_user(db: Session, user_id: int, notification_type: str, title: str, message: str = "", link: str | None = None):
    db.add(Notification(user_id=user_id, notification_type=notification_type, title=title, message=message, link=link))


def notify_roles(
    db: Session, roles: set[str], notification_type: str, title: str, message: str = "", link: str | None = None,
    exclude_user_id: int | None = None,
):
    users = db.query(User).join(Role).filter(Role.name.in_(roles), User.is_active.is_(True)).all()
    for user in users:
        if user.id != exclude_user_id:
            notify_user(db, user.id, notification_type, title, message, link)


SECURITY_TEAM = {"admin", "soc_analyst"}
