package go_django_sessions

import (
	"context"
	"database/sql"
	"errors"
)

// PostgreSQLStore uses Django's default django_session table with any registered
// PostgreSQL database/sql driver. Other databases can implement LoginStore.
type PostgreSQLStore struct{ DB *sql.DB }

func (s PostgreSQLStore) Load(ctx context.Context, key string) (*SessionRecord, error) {
	if s.DB == nil {
		return nil, errors.New("nil database")
	}
	var r SessionRecord
	err := s.DB.QueryRowContext(ctx, "SELECT session_data, expire_date FROM django_session WHERE session_key = $1", key).Scan(&r.Data, &r.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}
func (s PostgreSQLStore) Commit(ctx context.Context, oldKey, newKey string, expected, record *SessionRecord) error {
	if s.DB == nil || record == nil {
		return errors.New("database and session record are required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if expected != nil {
		var current SessionRecord
		err = tx.QueryRowContext(ctx, "SELECT session_data, expire_date FROM django_session WHERE session_key = $1 FOR UPDATE", oldKey).Scan(&current.Data, &current.ExpiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSessionInterrupted
		}
		if err != nil {
			return err
		}
		if current.Data != expected.Data || !current.ExpiresAt.Equal(expected.ExpiresAt) {
			return ErrSessionInterrupted
		}
	}
	if expected != nil && oldKey == newKey {
		_, err = tx.ExecContext(ctx, "UPDATE django_session SET session_data = $1, expire_date = $2 WHERE session_key = $3", record.Data, record.ExpiresAt, newKey)
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, "INSERT INTO django_session (session_key, session_data, expire_date) VALUES ($1, $2, $3) ON CONFLICT (session_key) DO NOTHING", newKey, record.Data, record.ExpiresAt)
		if err == nil {
			var n int64
			n, err = result.RowsAffected()
			if err == nil && n == 0 {
				return ErrSessionCollision
			}
		}
		if err == nil && expected != nil {
			_, err = tx.ExecContext(ctx, "DELETE FROM django_session WHERE session_key = $1", oldKey)
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s PostgreSQLStore) Delete(ctx context.Context, key string) error {
	if s.DB == nil {
		return errors.New("nil database")
	}
	_, err := s.DB.ExecContext(ctx, "DELETE FROM django_session WHERE session_key = $1", key)
	return err
}
