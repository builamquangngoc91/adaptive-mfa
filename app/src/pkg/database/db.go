package database

import (
	"adaptive-mfa/pkg/logger"
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"strings"
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
	logger.NewLogger().
		WithContext(ctx).
		With("tx", tx).
		Info("Starting transaction")

	if err := fn(ctx, tx); err != nil {
		logger.NewLogger().
			WithContext(ctx).
			With("tx", tx).
			With("error", err).
			Error("Rolling back transaction")
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return rollbackErr
		}
		return err
	}

	logger.NewLogger().
		WithContext(ctx).
		With("tx", tx).
		Info("Committing transaction")
	return tx.Commit()
}

func (d *Database) Ping(ctx context.Context) error {
	return d.db.PingContext(ctx)
}

func (d *Database) Close(ctx context.Context) error {
	return d.db.Close()
}

func (d *Database) Exec(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	d.logQuery(ctx, query, args...)
	return d.db.ExecContext(ctx, query, args...)
}

func (d *Database) Query(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	d.logQuery(ctx, query, args...)
	return d.db.QueryContext(ctx, query, args...)
}

func (d *Database) QueryRow(ctx context.Context, query string, args ...interface{}) *sql.Row {
	d.logQuery(ctx, query, args...)
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

func (d *Database) logQuery(ctx context.Context, query string, args ...interface{}) {
	logger.NewLogger().
		WithContext(ctx).
		With("query", query).
		With("args", args).
		With("query_parsed", d.parseSQL(query, args...)).
		Info("Executing query")
}

func (d *Database) parseSQL(query string, args ...interface{}) string {
	for i, arg := range args {
		if reflect.TypeOf(arg).Kind() == reflect.Pointer {
			arg = reflect.ValueOf(arg).Elem().Interface()
		}

		statementSymbol := fmt.Sprintf("$%d", i+1)
		switch v := arg.(type) {
		case string:
			query = strings.ReplaceAll(query, statementSymbol, v)
		case int, int8, int16, int32, int64:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%d", v))
		case float64:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%f", v))
		case time.Time:
			query = strings.ReplaceAll(query, statementSymbol, v.Format("2006-01-02 15:04:05"))
		case bool:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%t", v))
		case nil:
			query = strings.ReplaceAll(query, statementSymbol, "NULL")
		case []byte:
			query = strings.ReplaceAll(query, statementSymbol, string(v))
		case byte:
			query = strings.ReplaceAll(query, statementSymbol, fmt.Sprintf("%d", v))
		default:
			query = strings.ReplaceAll(query, statementSymbol, "NULL")
		}
	}
	return query
}
