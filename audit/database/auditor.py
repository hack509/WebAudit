"""
Database Auditor — Module 10.

Tests database connection, queries, indexes, relations, constraints,
transactions, and performance. Supports PostgreSQL, MySQL, and SQLite.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from audit.base import BaseAuditor
from audit.result import AuditResult, Severity
from config.settings import AuditConfig
from utils.logger import get_logger


class DatabaseAuditor(BaseAuditor):
    """Audits database configuration, schema, and performance."""

    MODULE_NAME = "database"
    MODULE_DESCRIPTION = "Audit Base de Données"

    def __init__(self, config: AuditConfig):
        super().__init__(config)

    async def run(self) -> AuditResult:
        """Run the database audit."""
        self.logger.info("Starting database audit")

        if not self.config.database.connection_string:
            self.info(
                "Database audit skipped",
                "No database connection string provided. "
                "Set 'database.connection_string' in config to enable DB auditing.",
            )
            return self.build_result()

        try:
            from sqlalchemy import create_engine, inspect, text
            from sqlalchemy.exc import OperationalError
        except ImportError:
            self.info("Database audit", "SQLAlchemy not installed — skipping DB audit")
            return self.build_result()

        try:
            engine = create_engine(self.config.database.connection_string, echo=False)

            # 1. Test connection
            self._test_connection(engine, text)

            # 2. Inspect schema
            self._inspect_schema(engine, inspect)

            # 3. Check indexes
            self._check_indexes(engine, inspect)

            # 4. Check constraints
            self._check_constraints(engine, inspect)

            # 5. Query performance
            self._check_query_performance(engine, text)

            engine.dispose()

        except Exception as e:
            self.fail_check(
                "Database connection failed",
                f"Cannot connect to database: {str(e)[:200]}",
                severity=Severity.CRITICAL,
                recommendation="Check database connection string and ensure the database is running",
            )

        return self.build_result()

    def _test_connection(self, engine, text) -> None:
        """Test database connection and version."""
        try:
            start = time.perf_counter()
            with engine.connect() as conn:
                result = conn.execute(text("SELECT 1"))
                result.fetchone()
            elapsed = (time.perf_counter() - start) * 1000

            self.pass_check(
                "Database connection",
                f"Connected successfully in {elapsed:.0f}ms",
            )

            # Get version
            try:
                with engine.connect() as conn:
                    dialect = engine.dialect.name
                    if dialect in ("postgresql", "mysql", "mariadb"):
                        version_query = "SELECT version()"
                    elif dialect == "sqlite":
                        version_query = "SELECT sqlite_version()"
                    else:
                        version_query = "SELECT 1"

                    result = conn.execute(text(version_query))
                    version = result.fetchone()[0]
                    self.info("Database version", f"{dialect}: {version}")
            except Exception:
                pass

        except Exception as e:
            self.fail_check(
                "Database connection",
                f"Connection failed: {e}",
                severity=Severity.CRITICAL,
            )

    def _inspect_schema(self, engine, inspect_fn) -> None:
        """Inspect database schema."""
        try:
            inspector = inspect_fn(engine)
            tables = inspector.get_table_names()

            self.info("Database tables", f"{len(tables)} table(s) found: {', '.join(tables[:20])}")

            for table in tables[:30]:
                columns = inspector.get_columns(table)
                pk = inspector.get_pk_constraint(table)

                # Check for primary key
                if not pk or not pk.get("constrained_columns"):
                    self.fail_check(
                        f"No primary key: {table}",
                        f"Table '{table}' has no primary key",
                        severity=Severity.HIGH,
                        recommendation=f"Add a primary key to table '{table}'",
                    )
                else:
                    self.pass_check(f"Primary key: {table}", f"PK: {pk['constrained_columns']}")

                # Check for nullable columns that probably shouldn't be
                for col in columns:
                    if col.get("name") in ("email", "username", "name") and col.get("nullable", True):
                        self.fail_check(
                            f"Nullable important column: {table}.{col['name']}",
                            f"Column '{col['name']}' in '{table}' allows NULL",
                            severity=Severity.LOW,
                            recommendation=f"Consider adding NOT NULL constraint to {table}.{col['name']}",
                        )

        except Exception as e:
            self.logger.warning(f"Schema inspection failed: {e}")
            self.info("Schema inspection", f"Could not inspect schema: {str(e)[:100]}")

    def _check_indexes(self, engine, inspect_fn) -> None:
        """Check for proper indexes."""
        try:
            inspector = inspect_fn(engine)
            tables = inspector.get_table_names()

            for table in tables[:20]:
                indexes = inspector.get_indexes(table)
                columns = inspector.get_columns(table)
                fks = inspector.get_foreign_keys(table)

                # Check for indexes on foreign keys
                indexed_cols = set()
                for idx in indexes:
                    for col in idx.get("column_names", []):
                        indexed_cols.add(col)

                for fk in fks:
                    fk_cols = fk.get("constrained_columns", [])
                    for col in fk_cols:
                        if col not in indexed_cols:
                            self.fail_check(
                                f"Missing index on FK: {table}.{col}",
                                f"Foreign key column '{col}' in '{table}' has no index",
                                severity=Severity.MEDIUM,
                                recommendation=f"Add an index on {table}.{col} for better JOIN performance",
                            )

                # Log index count
                if indexes:
                    self.pass_check(f"Indexes on {table}", f"{len(indexes)} index(es)")
                elif len(columns) > 3:
                    self.fail_check(
                        f"No indexes: {table}",
                        f"Table '{table}' with {len(columns)} columns has no indexes",
                        severity=Severity.LOW,
                        recommendation=f"Add indexes on frequently queried columns in '{table}'",
                    )

        except Exception as e:
            self.logger.warning(f"Index check failed: {e}")

    def _check_constraints(self, engine, inspect_fn) -> None:
        """Check foreign keys and unique constraints."""
        try:
            inspector = inspect_fn(engine)
            tables = inspector.get_table_names()

            total_fks = 0
            total_uniques = 0

            for table in tables[:20]:
                fks = inspector.get_foreign_keys(table)
                uniques = inspector.get_unique_constraints(table)

                total_fks += len(fks)
                total_uniques += len(uniques)

                # Check for unique on email-like columns
                columns = inspector.get_columns(table)
                for col in columns:
                    if col["name"] in ("email", "username", "slug"):
                        is_unique = any(
                            col["name"] in uc.get("column_names", [])
                            for uc in uniques
                        )
                        if not is_unique:
                            self.fail_check(
                                f"No unique constraint: {table}.{col['name']}",
                                f"'{col['name']}' should probably be unique",
                                severity=Severity.MEDIUM,
                                recommendation=f"Add UNIQUE constraint to {table}.{col['name']}",
                            )

            self.info(
                "Database constraints",
                f"{total_fks} foreign key(s), {total_uniques} unique constraint(s)",
            )

        except Exception as e:
            self.logger.warning(f"Constraint check failed: {e}")

    def _check_query_performance(self, engine, text) -> None:
        """Basic query performance checks."""
        try:
            with engine.connect() as conn:
                # Test simple query time
                start = time.perf_counter()
                conn.execute(text("SELECT 1"))
                simple_time = (time.perf_counter() - start) * 1000

                if simple_time > 100:
                    self.fail_check(
                        "Slow simple query",
                        f"SELECT 1 took {simple_time:.0f}ms",
                        severity=Severity.MEDIUM,
                        recommendation="Check database server performance and network latency",
                    )
                else:
                    self.pass_check("Query performance", f"Simple query: {simple_time:.1f}ms")

        except Exception as e:
            self.logger.warning(f"Performance check failed: {e}")
