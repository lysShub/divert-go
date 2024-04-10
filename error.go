package divert

type ErrLoaded struct{}

func (ErrLoaded) Error() string   { return "divert loaded" }
func (ErrLoaded) Temporary() bool { return true }

type ErrNotLoad struct{}

func (ErrNotLoad) Error() string { return "divert not load" }

type ErrShutdown struct{}

func (ErrShutdown) Error() string { return "divert handle shutdown" }

type ErrClosed struct{}

func (ErrClosed) Error() string { return "divert handle closed" }
