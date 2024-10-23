package server

type PersistentHandler interface {
	
}

type SQLiteManager struct {

}

func NewSQLiteManager() (PersistentHandler, error) {
	// db, err := database.ConnectDatabase()
	// if err != nil {
	// 	return nil, fmt.Errorf("error occured when connecting to db object: %v", err)
	// }
}