"""Ticket delivery state on the outbox (ADR-037).

A draft may now be sent, once, by someone other than its author. The payload stays immutable; only
the delivery columns can change and only along DRAFT|FAILED -> SENDING -> SENT|FAILED. SENT is
final, and the target never changes after the first attempt.

Revision ID: 0017
"""

from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

DELIVERY = "status, target, attempts, external_ref, external_url, last_error, attempted_at, sent_by, sent_at"


def upgrade() -> None:
    op.execute(f"""
    ALTER TABLE ticket_outbox DROP CONSTRAINT ticket_outbox_status_check;
    ALTER TABLE ticket_outbox
      ADD CONSTRAINT ticket_outbox_status_check
        CHECK (status IN ('DRAFT','SENDING','SENT','FAILED')),
      ADD COLUMN target text CHECK (target IN ('jira','servicenow')),
      ADD COLUMN attempts int NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 20),
      ADD COLUMN external_ref text CHECK (length(external_ref) BETWEEN 1 AND 100),
      ADD COLUMN external_url text CHECK (length(external_url) BETWEEN 1 AND 500),
      ADD COLUMN last_error text CHECK (last_error ~ '^[A-Z0-9_]{{1,40}}$'),
      ADD COLUMN attempted_at timestamptz,
      ADD COLUMN sent_by text,
      ADD COLUMN sent_at timestamptz,
      ADD CONSTRAINT ticket_outbox_sent_has_ref
        CHECK (status <> 'SENT' OR (external_ref IS NOT NULL AND sent_by IS NOT NULL
                                    AND sent_at IS NOT NULL)),
      ADD CONSTRAINT ticket_outbox_two_person CHECK (sent_by IS NULL OR sent_by <> created_by);

    CREATE FUNCTION aisw_ticket_transition() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'ticket_outbox rows are never deleted'; END IF;
      IF NOT ((OLD.status IN ('DRAFT','FAILED','SENDING') AND NEW.status = 'SENDING'
                 AND NEW.attempts = OLD.attempts + 1)
              OR (OLD.status = 'SENDING' AND NEW.status IN ('SENT','FAILED')
                 AND NEW.attempts = OLD.attempts)) THEN
        RAISE EXCEPTION 'ticket status cannot move from % to %', OLD.status, NEW.status;
      END IF;
      IF OLD.target IS NOT NULL AND NEW.target IS DISTINCT FROM OLD.target THEN
        RAISE EXCEPTION 'a ticket target never changes';
      END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER ticket_outbox_transition BEFORE UPDATE OR DELETE ON ticket_outbox
      FOR EACH ROW EXECUTE FUNCTION aisw_ticket_transition();
    GRANT UPDATE ({DELIVERY}) ON ticket_outbox TO aisw_app;
    """)


def downgrade() -> None:
    op.execute(f"""
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM ticket_outbox WHERE status <> 'DRAFT') THEN
        RAISE EXCEPTION 'tickets have been sent: 0017 cannot be downgraded';
      END IF;
    END $$;
    REVOKE UPDATE ({DELIVERY}) ON ticket_outbox FROM aisw_app;
    DROP TRIGGER ticket_outbox_transition ON ticket_outbox;
    DROP FUNCTION aisw_ticket_transition();
    ALTER TABLE ticket_outbox
      DROP CONSTRAINT ticket_outbox_two_person,
      DROP CONSTRAINT ticket_outbox_sent_has_ref,
      DROP COLUMN target, DROP COLUMN attempts, DROP COLUMN external_ref,
      DROP COLUMN external_url, DROP COLUMN last_error, DROP COLUMN attempted_at,
      DROP COLUMN sent_by, DROP COLUMN sent_at,
      DROP CONSTRAINT ticket_outbox_status_check,
      ADD CONSTRAINT ticket_outbox_status_check CHECK (status = 'DRAFT');
    """)  # noqa: S608
