package cli

import "time"

// suppressUntil is a suppression expiry inside the store's one-year bound (store.MaxSuppression).
var suppressUntil = time.Now().UTC().AddDate(0, 6, 0).Format("2006-01-02")
