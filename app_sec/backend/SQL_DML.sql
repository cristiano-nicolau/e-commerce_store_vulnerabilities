-- Adding products to the products table
INSERT INTO products (name, description, price, stock, category_id, photo)
VALUES
    ('DETIP Hoodie', 'Official hoodie of the Department of Telecommunications and Informatics Engineering.', 29.99, 100, 1, '../images/hoodie_nei.jpg'),
    ('DETIP Hat', 'Stylish hat with the DETIP logo embroidered.', 12.99, 200, 2, '../images/hoodie_nei.jpg'),
	('DETI T-shirt', 'Official DETI T-shirt with the department logo.', 19.99, 100, 1, '../images/emblema_lei.png'),
    ('DETI Emblem Lei', 'Emblem with Lei branding.', 9.99, 150, 2, '../images/emblema_lei.png'),
    ('DETI Emblem NEI', 'Emblem with NEI branding.', 9.99, 150, 2, '../images/emblema_nei.png'),
    ('DETI Backpack', 'Stylish backpack with multiple compartments for your tech gear.', 39.99, 50, 3, '../images/hoodie_nei.jpg'),
    ('DETI Sweatshirt', 'Warm and comfortable DETI Sweatshirt for the winter season.', 29.99, 75, 1, '../images/hoodie_nei.jpg'),
    ('DETI Mousepad', 'High-quality mousepad with a DETI design.', 7.99, 200, 4, '../images/emblema_lei.png'),
    ('DETI USB Drive', 'Custom DETI-themed USB drive for your data storage needs.', 12.99, 100, 5, '../images/emblema_lei'),
    ('DETI Notebook', 'Spiral-bound notebook with DETI branding for your notes.', 6.99, 150, 6, '../images/emblema_nei.png'),
    ('DETI Poster', 'Decorate your room with a DETI poster featuring iconic images.', 8.99, 50, 7, '../images/emblema_nei.png'),
    ;

-- Adding users
INSERT INTO users (first_name, email, password, type)
VALUES
    ('Admin','admin@example.com', 'password', 'admin'),
    ('Client', 'client@example.com', 'password', 'normal');


-- adding categories
INSERT INTO categories (name)
VALUES
    ('Clothes'), -- For clothing items like T-shirts and hoodies
    ('Drinkware'), -- For items like mugs
    ('Computer Accessories'), -- For items like mousepads and USB drives
    ('Clothing Accessories'), -- For items like notebooks
    ('Decor'), -- For decorative items like posters
    ('Tech Accessories'), -- For tech-related accessories
    ('Promotional Items'); -- For promotional products