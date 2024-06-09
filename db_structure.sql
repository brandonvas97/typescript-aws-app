DROP TABLE IF EXISTS users;
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  role VARCHAR(50),
  first_name VARCHAR(50),
  last_name VARCHAR(50),
  phone VARCHAR(10),
  email VARCHAR(50),
  username VARCHAR(30),
  password VARCHAR(200),
  address VARCHAR(50),
  gender VARCHAR(10),
  birth_date DATE,
  country VARCHAR(50),
  city VARCHAR(50),
  category VARCHAR(50),
  document_id INT,
  user_state VARCHAR(50),
  created_at DATE,
  updated_at DATE,
  deleted VARCHAR(50),
  deleted_at DATE
);
DROP TABLE IF EXISTS tokens;
CREATE TABLE tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  token VARCHAR(200),
  expiry_date INT,
  user_id INT,
  role_user_logged VARCHAR(50)
);
DROP TABLE IF EXISTS accounts;
CREATE TABLE accounts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  amount INT,
  user_id INT
);
DROP TABLE IF EXISTS transactions;
CREATE TABLE transactions(
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  amount INT,
  category VARCHAR(50),
  status VARCHAR(50),
  created_at DATE,
  updated_at DATE,
  deleted VARCHAR(50),
  deleted_at DATE,
  user_bet_id INT
);
DROP TABLE IF EXISTS bets;
CREATE TABLE bets(
  id INT AUTO_INCREMENT PRIMARY KEY,
  bet_option INT,
  sport VARCHAR(50),
  status VARCHAR(50),
  name VARCHAR(50),
  event_id VARCHAR(50),
  odd DOUBLE,
  result VARCHAR(50),
  created_at DATE,
  updated_at DATE,
  deleted VARCHAR(50),
  deleted_at DATE
);
DROP TABLE IF EXISTS users_bets;
CREATE TABLE users_bets(
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  bet_id VARCHAR(50),
  odd DOUBLE,
  amount INT,
  bet_option INT,
  state VARCHAR(50),
  created_at DATE,
  updated_at DATE,
  deleted VARCHAR(50),
  deleted_at DATE
);

INSERT INTO users(role, first_name, last_name, phone, email, username, password, address, gender, birth_date, country, city, category, document_id, user_state, created_at, updated_at, deleted, deleted_at)
VALUES('Admin', 'Brandon', 'Vasquez', '3017201357', 'brandvb97@gmail.com', 'brandon', '$2a$10$9GIF5A29cjmIJ9GnwsPIKu1b8g0BVbLEYZ9BxsnMfAql9NDycEkDe', 'Cra 20 #13-13', 'M', '1997-01-13', 'Colombia', 'Barranquilla', '1', 1, 'Active', '2024-06-05', NULL, 'NO', NULL),
('Admin', 'Laura', 'Alvarez', '3002154848', 'lalvarez@gmail.com', 'laura', '$2a$10$fTQjz6T.qbTf/ShgbcBEVuvwtmcgCMvlqbrkfW75Lx/YPbYxsgdPi', 'Cra 15 #44-35', 'F', '1998-12-20', 'Colombia', 'Medellin', '1', 1, 'Active', '2024-06-05', NULL, 'NO', NULL);


INSERT INTO bets(bet_option, sport, status, name, event_id, odd, created_at)
VALUES(1, 'Soccer', 'Active', 'Borussia Dortmund', '000001', 1.5, '2024-06-06'),
(2, 'Soccer', 'Active', 'Draw', '000001', 2, '2024-06-06'),
(3, 'Soccer', 'Active', 'Bayern Munich', '000001', 3, '2024-06-06'),
(1, 'Basketball', 'Active', 'L.A Lakers', '000002', 2.7, '2024-06-06'),
(2, 'Basketball', 'Active', 'Phoenix Suns', '000002', 2.8, '2024-06-06');