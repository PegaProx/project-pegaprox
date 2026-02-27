# -*- coding: utf-8 -*-
"""
PegaProx Caching & Rate Limiting - Layer 3
API rate limiter and storage data cache.
"""

import time
import threading
import logging
from collections import defaultdict

class APIRateLimiter:
    """Rate limiter for Proxmox API calls per cluster
    
    LW: We tested with 3000 VMs in our lab and the Proxmox API started returning 503s
    when we hit it too fast. This prevents that.
    """
    def __init__(self, calls_per_second=10, burst_limit=20):
        self.calls_per_second = calls_per_second
        self.burst_limit = burst_limit
        self._tokens = defaultdict(lambda: burst_limit)  # per-cluster tokens
        self._last_update = defaultdict(lambda: time.time())
        self._lock = threading.Lock()
    
    def acquire(self, cluster_id: str, timeout: float = 30.0) -> bool:
        """Acquire permission to make an API call. Returns False if timed out."""
        start_time = time.time()
        
        while True:
            with self._lock:
                now = time.time()
                elapsed = now - self._last_update[cluster_id]
                
                # Replenish tokens based on time passed
                self._tokens[cluster_id] = min(
                    self.burst_limit,
                    self._tokens[cluster_id] + (elapsed * self.calls_per_second)
                )
                self._last_update[cluster_id] = now
                
                if self._tokens[cluster_id] >= 1:
                    self._tokens[cluster_id] -= 1
                    return True
            
            # Check timeout
            if time.time() - start_time > timeout:
                logging.warning(f"API rate limit timeout for cluster {cluster_id}")
                return False
            
            # Wait a bit before retrying
            time.sleep(0.1)
    
    def get_stats(self, cluster_id: str) -> dict:
        """Get current rate limit stats for monitoring"""
        with self._lock:
            return {
                'available_tokens': round(self._tokens[cluster_id], 2),
                'max_tokens': self.burst_limit,
                'calls_per_second': self.calls_per_second
            }

# Global rate limiter instance
# MK: 10 calls/sec with burst of 20 should be safe for most Proxmox setups
# funny enough 15/30 worked fine with PVE 7.x but broke with 8.2 (stricter internal rate limit)
_api_rate_limiter = APIRateLimiter(calls_per_second=10, burst_limit=20)


# Caching layer for storage/VM data - reduces API calls significantly
class StorageDataCache:
    """Cache for storage and VM data to reduce Proxmox API load
    
    NS: With 2000 VMs, fetching all configs every minute was killing the API.
    Now we cache for 30-60 seconds and only refresh what we need.
    """
    def __init__(self):
        self._cache = {}  # { cluster_id: { key: { 'data': ..., 'expires': timestamp } } }
        self._lock = threading.Lock()
    
    def get(self, cluster_id: str, key: str) -> tuple:
        """Get cached data. Returns (data, hit) where hit is True if cache hit."""
        with self._lock:
            if cluster_id not in self._cache:
                return None, False
            
            entry = self._cache[cluster_id].get(key)
            if not entry:
                return None, False
            
            if time.time() > entry['expires']:
                del self._cache[cluster_id][key]
                return None, False
            
            return entry['data'], True
    
    def set(self, cluster_id: str, key: str, data: any, ttl_seconds: int = 30):
        """Cache data with TTL"""
        with self._lock:
            if cluster_id not in self._cache:
                self._cache[cluster_id] = {}
            
            self._cache[cluster_id][key] = {
                'data': data,
                'expires': time.time() + ttl_seconds
            }
    
    def invalidate(self, cluster_id: str, key: str = None):
        """Invalidate cache entry or entire cluster cache"""
        with self._lock:
            if cluster_id in self._cache:
                if key:
                    self._cache[cluster_id].pop(key, None)
                else:
                    del self._cache[cluster_id]
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        with self._lock:
            total_entries = sum(len(c) for c in self._cache.values())
            return {
                'clusters_cached': len(self._cache),
                'total_entries': total_entries
            }

# Global cache instance
_storage_cache = StorageDataCache()


