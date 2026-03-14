#!/bin/bash

curl -i -X POST http://localhost:8080/api/nodes/claim \
  -H "Authorization: Bearer pat_LDCdDUdMfl1D.APfnvMMVZZSj560k-xkiXZ6PObDmt4OIY8dvetLk9JE" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key":"test-pubkey-1",
    "hostname":"node-a",
    "metadata":{"env":"dev"}
  }'
