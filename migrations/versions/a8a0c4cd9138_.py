"""empty message

Revision ID: a8a0c4cd9138
Revises: 451b1e9f0cc2
Create Date: 2022-04-18 15:24:15.837678

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a8a0c4cd9138'
down_revision = '451b1e9f0cc2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('name', sa.String(length=64), nullable=True))
    op.add_column('users', sa.Column('location', sa.String(length=64), nullable=True))
    op.add_column('users', sa.Column('about_me', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('member_since', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('last_seen', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'last_seen')
    op.drop_column('users', 'member_since')
    op.drop_column('users', 'about_me')
    op.drop_column('users', 'location')
    op.drop_column('users', 'name')
    # ### end Alembic commands ###