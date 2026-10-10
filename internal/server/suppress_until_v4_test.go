package server

import "time"

// suppressUntilRFC is a suppression expiry inside the store's one-year bound (store.MaxSuppression).
var suppressUntilRFC = time.Now().UTC().AddDate(0, 6, 0).Format(time.RFC3339)
