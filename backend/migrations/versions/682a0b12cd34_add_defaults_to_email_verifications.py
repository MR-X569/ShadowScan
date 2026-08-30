"""add_defaults_to_email_verifications

Revision ID: 682a0b12cd34
Revises: 547b7d7f1f56
Create Date: 2026-08-30 14:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '682a0b12cd34'
down_revision: Union[str, Sequence[str], None] = '547b7d7f1f56'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to ensure email_verifications columns have server defaults."""
    op.alter_column(
        'email_verifications',
        'created_at',
        server_default=sa.text('now()'),
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
    )
    op.alter_column(
        'email_verifications',
        'attempts',
        server_default=sa.text('0'),
        existing_type=sa.Integer(),
        existing_nullable=False,
    )
    op.alter_column(
        'email_verifications',
        'used',
        server_default=sa.text('false'),
        existing_type=sa.Boolean(),
        existing_nullable=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column(
        'email_verifications',
        'used',
        server_default=None,
        existing_type=sa.Boolean(),
        existing_nullable=False,
    )
    op.alter_column(
        'email_verifications',
        'attempts',
        server_default=None,
        existing_type=sa.Integer(),
        existing_nullable=False,
    )
    op.alter_column(
        'email_verifications',
        'created_at',
        server_default=None,
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
    )
