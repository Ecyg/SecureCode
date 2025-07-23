# Use official PHP image with Apache
FROM php:8.2-apache

# Enable Apache mod_rewrite (optional, but common for PHP apps)
RUN a2enmod rewrite

# Copy app files to Apache document root
COPY . /var/www/html/

# Set permissions (optional, for dev)
RUN chown -R www-data:www-data /var/www/html

# Expose port 80
EXPOSE 80

# Start Apache in the foreground
CMD ["apache2-foreground"] 