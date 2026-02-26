from unittest.mock import Mock
import pytest
from seedpass.core.stats_manager import StatsManager

def test_stats_manager_reset():
    """Test that StatsManager.reset correctly resets the displayed flag."""
    stats_manager = StatsManager()
    manager = Mock()

    # Initial call should display stats
    stats_manager.display_stats_once(manager)
    manager.display_stats.assert_called_once()

    # Second call should not display stats again
    manager.reset_mock()
    stats_manager.display_stats_once(manager)
    manager.display_stats.assert_not_called()

    # Reset the stats manager
    stats_manager.reset()

    # Call after reset should display stats again
    stats_manager.display_stats_once(manager)
    manager.display_stats.assert_called_once()
