#!/bin/bash
sudo spire-server jwt mint --spiffeID spiffe://example.org/middletie --audience spiffe://example.org/middletier
