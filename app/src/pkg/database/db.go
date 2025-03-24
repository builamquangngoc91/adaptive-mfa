package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// TODO: Add logger

type IDatabase interface {
	GetDB() *sql.DB
	Ping(ctx context.Context) error
	Close(ctx context.Context) error
	StartTx(ctx context.Context, fn TxFunc, opts *sql.TxOptions) error
	Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row
	Prepare(ctx context.Context, query string) (*sql.Stmt, error)
	ExecTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (sql.Result, error)
	QueryTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) *sql.Row
	PrepareTx(ctx context.Context, tx *sql.Tx, query string) (*sql.Stmt, error)
}

type DatabaseConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	DBName          string
	Schema          string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type Database struct {
	db *sql.DB
}

func NewDatabase(cfg *DatabaseConfig) (IDatabase, error) {
	db, err := sql.Open("postgres", makeDSN(cfg))
	if err != nil {
		return nil, err
	}

	// Setup connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	return &Database{db: db}, nil
}

func makeDSN(cfg *DatabaseConfig) string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)
}

func (d *Database) GetDB() *sql.DB {
	return d.db
}

type TxFunc func(ctx context.Context, tx *sql.Tx) error

func (d *Database) StartTx(ctx context.Context, fn TxFunc, opts *sql.TxOptions) error {
	tx, err := d.db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}

	if err := fn(ctx, tx); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	return tx.Commit()
}

func (d *Database) Ping(ctx context.Context) error {
	return d.db.PingContext(ctx)
}

func (d *Database) Close(ctx context.Context) error {
	return d.db.Close()
}

func (d *Database) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return d.db.ExecContext(ctx, query, args...)
}

func (d *Database) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return d.db.QueryContext(ctx, query, args...)
}

func (d *Database) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return d.db.QueryRowContext(ctx, query, args...)
}

func (d *Database) Prepare(ctx context.Context, query string) (*sql.Stmt, error) {
	return d.db.PrepareContext(ctx, query)
}

func (d *Database) ExecTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (sql.Result, error) {
	if tx == nil {
		return d.Exec(ctx, query, args...)
	}
	return tx.ExecContext(ctx, query, args...)
}

func (d *Database) QueryTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) (*sql.Rows, error) {
	if tx == nil {
		return d.Query(ctx, query, args...)
	}
	return tx.QueryContext(ctx, query, args...)
}

func (d *Database) QueryRowTx(ctx context.Context, tx *sql.Tx, query string, args ...interface{}) *sql.Row {
	if tx == nil {
		return d.QueryRow(ctx, query, args...)
	}
	return tx.QueryRowContext(ctx, query, args...)
}

func (d *Database) PrepareTx(ctx context.Context, tx *sql.Tx, query string) (*sql.Stmt, error) {
	if tx == nil {
		return d.Prepare(ctx, query)
	}
	return tx.PrepareContext(ctx, query)
}
