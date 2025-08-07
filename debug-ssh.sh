#!/bin/bash

# Debug script to test SSH connectivity issues

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "SSH Connection Debugging Script"
echo "========================================="
echo ""

# Parse hosts.ini for connection details
USER=$(grep "ssh_user" hosts.ini | cut -d'=' -f2 | tr -d ' "')
PASSWORD=$(grep "^password" hosts.ini | cut -d'=' -f2 | tr -d ' "')
PORT=$(grep "ssh_port" hosts.ini | cut -d'=' -f2 | tr -d ' ')
BECOME_PASS=$(grep "become_pass" hosts.ini | cut -d'=' -f2 | tr -d ' "')

echo "Configuration from hosts.ini:"
echo "  User: $USER"
echo "  Port: $PORT"
echo "  Password configured: $([ -n "$PASSWORD" ] && echo "Yes" || echo "No")"
echo "  Become password: $([ -n "$BECOME_PASS" ] && echo "Yes" || echo "No")"
echo ""

# Get hosts
HOSTS=$(grep -A 100 '^\[rhel_hosts\]' hosts.ini | grep -E '^[0-9]+\.' | awk '{print $1}')

if [ -z "$HOSTS" ]; then
    echo -e "${RED}No hosts found in hosts.ini!${NC}"
    exit 1
fi

echo "Hosts to test:"
for host in $HOSTS; do
    echo "  - $host"
done
echo ""

# Test each host
for host in $HOSTS; do
    echo "----------------------------------------"
    echo "Testing host: $host"
    echo "----------------------------------------"
    
    # Test 1: Basic connectivity
    echo -n "1. Testing network connectivity (ping)... "
    if ping -c 1 -W 2 $host >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        echo "   Cannot ping $host - check network/firewall"
        continue
    fi
    
    # Test 2: SSH port connectivity
    echo -n "2. Testing SSH port $PORT... "
    if timeout 5 nc -zv $host $PORT >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        echo "   Port $PORT not reachable - check if SSH is running"
        continue
    fi
    
    # Test 3: SSH key authentication
    echo -n "3. Testing SSH key authentication... "
    if timeout 10 ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
        -p $PORT $USER@$host "echo test" >/dev/null 2>&1; then
        echo -e "${GREEN}OK (Key auth works!)${NC}"
        SSH_METHOD="key"
    else
        echo -e "${YELLOW}Key auth failed, will try password${NC}"
        SSH_METHOD="password"
    fi
    
    # Test 4: SSH with password (if needed)
    if [ "$SSH_METHOD" = "password" ]; then
        echo -n "4. Testing SSH password authentication... "
        if [ -n "$PASSWORD" ]; then
            if timeout 10 sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no \
                -p $PORT $USER@$host "echo test" >/dev/null 2>&1; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${RED}FAILED${NC}"
                echo "   Password authentication failed - check credentials"
                echo ""
                echo "   Debug: Try manually:"
                echo "   ssh -p $PORT $USER@$host"
                continue
            fi
        else
            echo -e "${RED}No password configured${NC}"
            continue
        fi
    fi
    
    # Test 5: Test sudo access
    echo -n "5. Testing sudo access... "
    if [ "$SSH_METHOD" = "key" ]; then
        SUDO_TEST=$(timeout 10 ssh -o StrictHostKeyChecking=no -p $PORT $USER@$host \
            "echo '$BECOME_PASS' | sudo -S echo 'sudo works'" 2>&1)
    else
        SUDO_TEST=$(timeout 10 sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no \
            -p $PORT $USER@$host "echo '$BECOME_PASS' | sudo -S echo 'sudo works'" 2>&1)
    fi
    
    if echo "$SUDO_TEST" | grep -q "sudo works"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}WARNING - sudo might not work${NC}"
        echo "   Output: $SUDO_TEST"
    fi
    
    # Test 6: Run a real command
    echo -n "6. Testing real command execution... "
    if [ "$SSH_METHOD" = "key" ]; then
        CMD_OUTPUT=$(timeout 10 ssh -o StrictHostKeyChecking=no -p $PORT $USER@$host \
            "hostname -f" 2>&1)
    else
        CMD_OUTPUT=$(timeout 10 sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no \
            -p $PORT $USER@$host "hostname -f" 2>&1)
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}OK${NC} (hostname: $CMD_OUTPUT)"
    else
        echo -e "${RED}FAILED${NC}"
        echo "   Error: $CMD_OUTPUT"
    fi
    
    echo ""
done

echo "========================================="
echo "Summary:"
echo ""
echo "If all tests passed, the health check should work."
echo "If tests failed, fix the issues above first."
echo ""
echo "Common fixes:"
echo "1. SSH key not working? Run: ssh-copy-id $USER@<host>"
echo "2. Password auth failing? Check the password in hosts.ini"
echo "3. Sudo not working? Check become_pass in hosts.ini"
echo "4. Connection timeout? Check firewall/network settings"
echo "========================================="
