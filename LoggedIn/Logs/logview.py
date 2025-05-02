import matplotlib.pyplot as plt
import numpy as np
from typing import List, Tuple, Dict, Any
from datetime import datetime
from dataclasses import dataclass

@dataclass
class VisualizationResult:
    figure: plt.Figure
    name: str
    description: str
    related_log_ids: List[int]

class LogView:
    def __init__(self, data_manager):
        self.data_manager = data_manager
        self.style_settings = {
            'title_fontsize': 16,
            'label_fontsize': 12,
            'tick_fontsize': 10,
            'colors': {
                'success': '#4cc9f0',
                'failure': '#f72585',
                'warning': '#ff9e00',
                'neutral': '#adb5bd'
            }
        }

    def plot_failed_logins(self, analyser) -> VisualizationResult:
        """Plot failed login attempts by user."""
        data = analyser.count_failed_logins()
        if not data:
            print("No failed login data to display")
            return None

        users = [item[0] for item in data]
        counts = [item[1] for item in data]
        related_log_ids = [item[2] for item in data]  # Assuming analyser returns log IDs

        fig = plt.figure(figsize=(12, 6))
        bars = plt.bar(users, counts, color=self.style_settings['colors']['failure'])

        # Add value labels
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom')

        self._apply_style(
            title='Failed Login Attempts by User',
            xlabel='Username',
            ylabel='Failed Attempts'
        )
        
        return VisualizationResult(
            figure=fig,
            name='failed_logins',
            description='Bar chart showing failed login attempts by user',
            related_log_ids=related_log_ids
        )

    def plot_login_timeline(self, analyser) -> VisualizationResult:
        """Plot login activity timeline by hour."""
        timeline_data = analyser.get_login_timeline()
        if not timeline_data:
            print("No timeline data to display")
            return None

        # Process timeline data
        hours = []
        success_counts = []
        failure_counts = []
        related_log_ids = []
        
        for hour_data in timeline_data:
            hours.append(hour_data['hour'])
            success_counts.append(hour_data['success_count'])
            failure_counts.append(hour_data['failure_count'])
            related_log_ids.extend(hour_data['related_log_ids'])

        fig = plt.figure(figsize=(14, 6))
        bar_width = 0.35
        index = np.arange(len(hours))

        plt.bar(
            index, 
            success_counts, 
            bar_width, 
            label='Successful Logins', 
            color=self.style_settings['colors']['success']
        )
        plt.bar(
            index + bar_width, 
            failure_counts, 
            bar_width, 
            label='Failed Logins', 
            color=self.style_settings['colors']['failure']
        )

        self._apply_style(
            title='Login Activity by Hour',
            xlabel='Hour of Day',
            ylabel='Number of Logins',
            xticks=index + bar_width / 2,
            xticklabels=hours,
            legend=True
        )
        
        return VisualizationResult(
            figure=fig,
            name='login_timeline',
            description='Stacked bar chart showing login activity by hour',
            related_log_ids=related_log_ids
        )

    def _apply_style(self, **kwargs):
        """Apply consistent styling to plots."""
        if 'title' in kwargs:
            plt.title(
                kwargs['title'],
                pad=20,
                fontsize=self.style_settings['title_fontsize']
            )
        
        if 'xlabel' in kwargs:
            plt.xlabel(
                kwargs['xlabel'],
                labelpad=10,
                fontsize=self.style_settings['label_fontsize']
            )
        
        if 'ylabel' in kwargs:
            plt.ylabel(
                kwargs['ylabel'],
                labelpad=10,
                fontsize=self.style_settings['label_fontsize']
            )
        
        if 'xticks' in kwargs and 'xticklabels' in kwargs:
            plt.xticks(
                kwargs['xticks'],
                kwargs['xticklabels'],
                rotation=45,
                fontsize=self.style_settings['tick_fontsize']
            )
        
        if kwargs.get('legend'):
            plt.legend(fontsize=self.style_settings['label_fontsize'])
        
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()