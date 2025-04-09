# migrations/versions/592c253b01b0_added_date_column.py
from alembic import op
import sqlalchemy as sa
from datetime import datetime

# revision identifiers, used by Alembic.
revision = '592c253b01b0'
down_revision = None  # or the previous revision ID
branch_labels = None
depends_on = None

def upgrade():
    # Add the `added_date` column
    op.add_column('reminder', sa.Column('added_date', sa.DateTime(), default=datetime.utcnow))

def downgrade():
    # Drop the `added_date` column in case of rollback
    op.drop_column('reminder', 'added_date')
