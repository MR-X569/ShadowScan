"""add indexes and finding fields

Revision ID: 9c2f8e12ab34
Revises: 1ba1210a6450
Create Date: 2026-08-26 20:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9c2f8e12ab34'
down_revision: Union[str, Sequence[str], None] = '1ba1210a6450'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add indexes for foreign keys
    op.create_index(op.f('ix_scans_user_id'), 'scans', ['user_id'], unique=False)
    op.create_index(op.f('ix_email_verifications_user_id'), 'email_verifications', ['user_id'], unique=False)
    op.create_index(op.f('ix_findings_scan_id'), 'findings', ['scan_id'], unique=False)

    # Add extra columns to findings
    op.add_column('findings', sa.Column('plugin', sa.String(length=100), nullable=True))
    op.add_column('findings', sa.Column('evidence', sa.Text(), nullable=True))
    op.add_column(
        'findings',
        sa.Column(
            'created_at',
            sa.DateTime(timezone=True),
            server_default=sa.text('now()'),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column('findings', 'created_at')
    op.drop_column('findings', 'evidence')
    op.drop_column('findings', 'plugin')
    op.drop_index(op.f('ix_findings_scan_id'), table_name='findings')
    op.drop_index(op.f('ix_email_verifications_user_id'), table_name='email_verifications')
    op.drop_index(op.f('ix_scans_user_id'), table_name='scans')
