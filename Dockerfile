# Use official PHP image with Apache
FROM php:8.2-apache

# Install git
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Clone the repo from GitHub (replace the URL with your actual repo)
RUN git clone https://github.com/Ecyg/SecureCode.git /var/www/html

# Enable Apache mod_rewrite (optional, but common for PHP apps)
RUN a2enmod rewrite

# Set permissions (optional, for dev)
RUN chown -R www-data:www-data /var/www/html

# Expose port 80
EXPOSE 80

# Start Apache in the foreground
CMD ["apache2-foreground"] 