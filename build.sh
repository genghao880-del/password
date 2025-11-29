#!/bin/bash
# Cloudflare Pages build script
# This script prepares the project for deployment

echo "Removing node_modules before deployment..."
rm -rf node_modules

echo "Build complete - ready for deployment"
