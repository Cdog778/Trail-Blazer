#!/bin/bash

set -e  # exit on error

ACCOUNT_ID=732406385148
REGION=us-west-1
REPO=iam-baseline-engine
IMAGE_TAG=latest

echo "[1/3] Building Docker image..."
docker build -t $REPO .

echo "[2/3] Tagging image for ECR..."
docker tag $REPO:$IMAGE_TAG $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO:$IMAGE_TAG

echo "[3/3] Pushing image to ECR..."
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO:$IMAGE_TAG

echo "Deployed $REPO:$IMAGE_TAG to ECR"

