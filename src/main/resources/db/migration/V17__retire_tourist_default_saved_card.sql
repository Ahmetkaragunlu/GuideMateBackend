UPDATE saved_payment_methods
SET is_default = FALSE,
    default_guard = NULL
WHERE is_default = TRUE
   OR default_guard IS NOT NULL;

ALTER TABLE saved_payment_methods
    ALTER COLUMN is_default SET DEFAULT FALSE;
