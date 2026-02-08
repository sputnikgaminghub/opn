"""Task system models.

Integrated into the existing wallet-first user model in app.py.

Locked spec:
- Reward is fixed per task.
- Proof is a URL.
- One submission per (wallet, task). If declined, user can resubmit and we overwrite
  the existing submission row (enforced via unique constraint).
- On approval, user.task_points increments by task.reward and we insert a ledger row.
"""

from datetime import datetime

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

# app.py defines the SQLAlchemy instance `db`.
from extensions import db


TASK_STATUS_PENDING = "pending"
TASK_STATUS_APPROVED = "approved"
TASK_STATUS_DECLINED = "declined"


class Task(db.Model):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    task_link = Column(String(500), nullable=True)  # optional URL to perform the task
    reward = Column(Integer, nullable=False, default=0)  # fixed reward (task_points)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    submissions = relationship("TaskSubmission", back_populates="task", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_tasks_active", "is_active"),
        Index("idx_tasks_created", "created_at"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "task_link": self.task_link,
            "reward": self.reward,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class TaskSubmission(db.Model):
    __tablename__ = "task_submissions"

    id = Column(Integer, primary_key=True)
    user_wallet = Column(String(42), ForeignKey("users.wallet"), nullable=False, index=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False, index=True)

    proof_url = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default=TASK_STATUS_PENDING)
    review_note = Column(Text, nullable=True)

    submitted_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    reviewed_at = Column(DateTime, nullable=True)

    task = relationship("Task", back_populates="submissions")

    __table_args__ = (
        UniqueConstraint("user_wallet", "task_id", name="uq_task_submission_wallet_task"),
        Index("idx_task_submissions_status", "status"),
        Index("idx_task_submissions_submitted", "submitted_at"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_wallet": self.user_wallet,
            "task_id": self.task_id,
            "proof_url": self.proof_url,
            "status": self.status,
            "review_note": self.review_note,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
        }


class TaskRewardTransaction(db.Model):
    __tablename__ = "task_reward_transactions"

    id = Column(Integer, primary_key=True)
    user_wallet = Column(String(42), ForeignKey("users.wallet"), nullable=False, index=True)
    task_id = Column(Integer, ForeignKey("tasks.id"), nullable=False, index=True)
    amount = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_task_rewards_wallet_created", "user_wallet", "created_at"),
        Index("idx_task_rewards_task_created", "task_id", "created_at"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_wallet": self.user_wallet,
            "task_id": self.task_id,
            "amount": self.amount,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }