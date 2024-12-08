-- Create Database
CREATE DATABASE FoodDonationDB;

USE FoodDonationDB;

CREATE USER 'admin_user'@'root' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON FoodDonationDB.* TO 'admin_user'@'root';

-- Table: User
CREATE TABLE User (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    phone_number VARCHAR(15),
	last_login DATETIME DEFAULT NULL,
    role ENUM('Donor', 'Recipient', 'Admin') NOT NULL,
    CONSTRAINT chk_email_format CHECK (email LIKE '%_@__%.__%'),
    CONSTRAINT chk_phone_format CHECK (phone_number REGEXP '^[0-9]{10,15}$')
);

SET @hashed_password = SHA2('your_password', 256);

INSERT INTO User (username, email, password_hash, phone_number, role)
VALUES ('admin_user', 'admin_user@root.com', @hashed_password, '9876543210', 'Admin');

-- Table: Organization
CREATE TABLE Organization (
    organization_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    address TEXT NOT NULL,
    contact_info VARCHAR(255),
    capacity INT,
    registration_date DATE NOT NULL,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES User(user_id) 
		ON UPDATE CASCADE ON DELETE CASCADE
);

-- Table: Categories
CREATE TABLE Categories (
    category_name VARCHAR(50) PRIMARY KEY,
    description TEXT
);

-- Default categories in the Categories table
INSERT INTO Categories (category_name, description) VALUES
('Perishable', 'Foods that need refrigeration and have a short shelf life, such as dairy, fruits, and vegetables.'),
('Non-Perishable', 'Foods that do not require refrigeration and have a long shelf life, such as canned goods and dry foods.'),
('Baked Goods', 'Items such as bread, pastries, and cakes.'),
('Frozen', 'Foods that are stored in a frozen state, such as frozen meats and meals.'),
('Beverages', 'Drinks such as juices, water, and soft drinks.'),
('Snacks', 'Packaged snacks such as chips, cookies, and nuts.'),
('Prepared Meals', 'Cooked meals ready for immediate consumption.'),
('Baby Food', 'Food products specifically made for infants and toddlers.'),
('Condiments', 'Sauces, spices, and spreads such as ketchup, mustard, and peanut butter.'),
('Grains', 'Staples such as rice, wheat, pasta, and cereals.');

-- Table: Donations
CREATE TABLE Donations (
    donation_id INT AUTO_INCREMENT PRIMARY KEY,
    donation_date DATE NOT NULL,
    status ENUM('Pending', 'Completed', 'Cancelled') NOT NULL,
    delivery_method ENUM('Pickup', 'Delivery') NOT NULL,
    delivery_location TEXT,
    recipient_id INT,
    donor_id INT NOT NULL,
    FOREIGN KEY (recipient_id) REFERENCES Organization(organization_id) 
		ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (donor_id) REFERENCES User(user_id) 
		ON UPDATE CASCADE ON DELETE CASCADE
);

-- Table: FoodItems
CREATE TABLE FoodItems (
    food_item_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    origin VARCHAR(100),
    storage_requirements TEXT,
    expiration_date DATE NOT NULL,
    category_name VARCHAR(50) NOT NULL,
    donation_id INT NOT NULL,
    FOREIGN KEY (category_name) REFERENCES Categories(category_name)
		ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (donation_id) REFERENCES Donations(donation_id)
		ON UPDATE CASCADE ON DELETE CASCADE
);

-- Table: Notifications
CREATE TABLE Notifications (
    notification_id INT AUTO_INCREMENT PRIMARY KEY,
    message TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    donor_id INT NULL,
    user_id INT NULL,
    organization_id INT NULL,
    FOREIGN KEY (donor_id) REFERENCES User(user_id) 
		ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES User(user_id) 
		ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES Organization(organization_id)
		ON UPDATE CASCADE ON DELETE CASCADE
);

-- Table: DonationStatistics
CREATE TABLE DonationStatistics (
    stat_id INT AUTO_INCREMENT PRIMARY KEY,   
    admin_user_id INT NOT NULL,              
    stat_date DATE NOT NULL UNIQUE,          
    total_donations INT NOT NULL DEFAULT 0,   
    completed_donations INT NOT NULL DEFAULT 0, 
    pending_donations INT NOT NULL DEFAULT 0, 
    cancelled_donations INT NOT NULL DEFAULT 0, 
    FOREIGN KEY (admin_user_id) REFERENCES User(user_id)
		ON UPDATE CASCADE ON DELETE CASCADE
);

-- Table: DonationFeedback
CREATE TABLE DonationFeedback (
    feedback_id INT AUTO_INCREMENT PRIMARY KEY,      
    donation_id INT NOT NULL,                         
    user_id INT NOT NULL,                             
    feedback TEXT NOT NULL,                           
    rating INT CHECK (rating BETWEEN 1 AND 5),        
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,    
    FOREIGN KEY (donation_id) REFERENCES Donations(donation_id) 
		ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES User(user_id) 
		ON UPDATE CASCADE ON DELETE CASCADE
);

-- Table: UserActions
CREATE TABLE UserActions (
    action_id INT AUTO_INCREMENT PRIMARY KEY, 
    user_id INT NOT NULL,                     
    action_type ENUM(
        'Login', 
        'Donation',  
        'Notification'
    ) NOT NULL,                              
    action_details TEXT,                       
    action_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, 
    FOREIGN KEY (user_id) REFERENCES User(user_id) 
		ON UPDATE CASCADE ON DELETE CASCADE 
);


DELIMITER $$

CREATE TRIGGER enforce_admin_user_role
BEFORE INSERT ON DonationStatistics
FOR EACH ROW
BEGIN
    DECLARE admin_check INT;
    SELECT COUNT(*) INTO admin_check
    FROM User
    WHERE user_id = NEW.admin_user_id AND role = 'Admin';

    IF admin_check = 0 THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'The admin_user_id must correspond to a user with the role "Admin".';
    END IF;
END $$

DELIMITER ;


DELIMITER $$

CREATE TRIGGER Alert_Donation_Status
BEFORE UPDATE ON Donations
FOR EACH ROW
BEGIN
    DECLARE donor_notification_message TEXT;
    DECLARE recipient_notification_message TEXT;
    IF (OLD.status = 'Completed' OR OLD.status = 'Cancelled') AND NOT (NEW.status <=> OLD.status) THEN
        SIGNAL SQLSTATE '45000' 
        SET MESSAGE_TEXT = 'Status cannot be changed once it is set to Completed or Cancelled.';
    END IF;
    IF NOT (OLD.status <=> NEW.status) THEN
        CASE NEW.status
            WHEN 'Completed' THEN
                SET donor_notification_message = CONCAT(
                    'Thank you for your generous donation (Donation ID: ', NEW.donation_id, ') to the recipient.'
                );

                SET recipient_notification_message = CONCAT(
                    'Donation ID ', NEW.donation_id, ' has been successfully marked as received.'
                );

                INSERT INTO Notifications (user_id, message, created_at)
                SELECT NEW.donor_id, donor_notification_message, NOW()
                FROM DUAL
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM Notifications
                    WHERE user_id = NEW.donor_id
                      AND message = donor_notification_message
                );

                INSERT INTO Notifications (user_id, message, created_at, organization_id)
                SELECT u.user_id, recipient_notification_message, NOW(), NEW.recipient_id
                FROM Organization o
                JOIN User u ON o.user_id = u.user_id
                WHERE o.organization_id = NEW.recipient_id
                AND NOT EXISTS (
                    SELECT 1
                    FROM Notifications
                    WHERE user_id = u.user_id
                      AND message = recipient_notification_message
                );

            WHEN 'Cancelled' THEN
                SET donor_notification_message = CONCAT(
                    'Donation ID ', NEW.donation_id, ' request has been canceled by the recipient.'
                );

                SET recipient_notification_message = CONCAT(
                    'Donation ID ', NEW.donation_id, ' has been successfully canceled.'
                );

                INSERT INTO Notifications (user_id, message, created_at)
                SELECT NEW.donor_id, donor_notification_message, NOW()
                FROM DUAL
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM Notifications
                    WHERE user_id = NEW.donor_id
                      AND message = donor_notification_message
                );

                INSERT INTO Notifications (user_id, message, created_at, organization_id)
                SELECT u.user_id, recipient_notification_message, NOW(), NEW.recipient_id
                FROM Organization o
                JOIN User u ON o.user_id = u.user_id
                WHERE o.organization_id = NEW.recipient_id
                AND NOT EXISTS (
                    SELECT 1
                    FROM Notifications
                    WHERE user_id = u.user_id
                      AND message = recipient_notification_message
                );
        END CASE;
    END IF;
END$$

DELIMITER ;


DELIMITER $$

CREATE TRIGGER Notify_Expiration_Alert
AFTER INSERT ON FoodItems
FOR EACH ROW
BEGIN
    DECLARE expiration_alert_message TEXT;
    DECLARE days_to_expiration INT;

    SET days_to_expiration = DATEDIFF(NEW.expiration_date, CURDATE());

    IF days_to_expiration <= 7 AND days_to_expiration >= 0 THEN
        SET expiration_alert_message = CONCAT(
            'Your donation (Donation ID: ', NEW.donation_id, ') is nearing expiration. It will expire on ', 
            NEW.expiration_date, '.'
        );

        INSERT INTO Notifications (user_id, message, created_at)
        SELECT d.donor_id, expiration_alert_message, NOW()
        FROM Donations d
        WHERE d.donation_id = NEW.donation_id AND d.status = 'Pending';
    END IF;
END$$

DELIMITER ;


DELIMITER $$

CREATE TRIGGER LogUserLogin
AFTER UPDATE ON User
FOR EACH ROW
BEGIN
    
    IF OLD.last_login IS NULL OR OLD.last_login <> NEW.last_login THEN
        INSERT INTO UserActions (user_id, action_type, action_details, action_timestamp)
        VALUES (NEW.user_id, 'Login', CONCAT('User ', NEW.username, ' logged in at ', NEW.last_login), NOW());
    END IF;
END$$

DELIMITER ;


DELIMITER $$

CREATE TRIGGER LogDonationAction
AFTER INSERT ON Donations
FOR EACH ROW
BEGIN
    INSERT INTO UserActions (user_id, action_type, action_details)
    VALUES (NEW.donor_id, 'Donation', CONCAT('Donation ID ', NEW.donation_id, ' created with status ', NEW.status));
END$$

DELIMITER ;


DELIMITER $$

CREATE TRIGGER LogNotificationAction
AFTER INSERT ON Notifications
FOR EACH ROW
BEGIN
    INSERT INTO UserActions (user_id, action_type, action_details)
    VALUES (NEW.user_id, 'Notification', NEW.message);
END$$

DELIMITER ;









