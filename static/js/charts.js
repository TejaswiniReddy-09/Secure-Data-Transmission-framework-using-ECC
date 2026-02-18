// Enhanced Charting functionality
class PerformanceCharts {
    constructor() {
        this.charts = new Map();
        this.init();
    }

    init() {
        this.loadOperationData();
        this.setupChartInteractions();
    }

    async loadOperationData() {
        try {
            const response = await fetch('/get_operations');
            const data = await response.json();
            
            if (!data.error) {
                this.renderAllCharts(data);
            }
        } catch (error) {
            console.error('Error loading operation data:', error);
        }
    }

    renderAllCharts(data) {
        this.renderPerformanceChart(data);
        this.renderAlgorithmComparison(data);
        this.renderOperationTypes(data);
    }

    renderPerformanceChart(data) {
        const ctx = document.getElementById('performanceChart');
        if (!ctx) return;

        this.charts.set('performance', new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.algorithms,
                datasets: [
                    {
                        label: 'Encryption Time (s)',
                        data: data.encryption_times,
                        backgroundColor: 'rgba(255, 107, 53, 0.8)',
                        borderColor: 'rgba(255, 107, 53, 1)',
                        borderWidth: 2,
                        borderRadius: 5
                    },
                    {
                        label: 'Decryption Time (s)',
                        data: data.decryption_times,
                        backgroundColor: 'rgba(243, 156, 18, 0.8)',
                        borderColor: 'rgba(243, 156, 18, 1)',
                        borderWidth: 2,
                        borderRadius: 5
                    }
                ]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Operation Performance',
                        font: { size: 16, weight: 'bold' }
                    },
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Time (seconds)'
                        },
                        grid: {
                            color: 'rgba(0,0,0,0.1)'
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                },
                interaction: {
                    mode: 'nearest',
                    axis: 'x',
                    intersect: false
                }
            }
        }));
    }

    renderAlgorithmComparison(data) {
        const ctx = document.getElementById('algorithmChart');
        if (!ctx) return;

        // Calculate averages for each algorithm
        const algorithmData = this.processAlgorithmData(data);
        
        this.charts.set('algorithm', new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['Speed', 'Security', 'Capacity', 'Reliability', 'Efficiency'],
                datasets: [
                    {
                        label: 'Curve25519',
                        data: [9, 7, 8, 9, 8],
                        backgroundColor: 'rgba(255, 107, 53, 0.2)',
                        borderColor: 'rgba(255, 107, 53, 1)',
                        pointBackgroundColor: 'rgba(255, 107, 53, 1)',
                        pointBorderColor: '#fff',
                        pointHoverBackgroundColor: '#fff',
                        pointHoverBorderColor: 'rgba(255, 107, 53, 1)'
                    },
                    {
                        label: 'SECP256R1',
                        data: [7, 9, 7, 8, 7],
                        backgroundColor: 'rgba(243, 156, 18, 0.2)',
                        borderColor: 'rgba(243, 156, 18, 1)',
                        pointBackgroundColor: 'rgba(243, 156, 18, 1)',
                        pointBorderColor: '#fff',
                        pointHoverBackgroundColor: '#fff',
                        pointHoverBorderColor: 'rgba(243, 156, 18, 1)'
                    }
                ]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Algorithm Comparison'
                    },
                    legend: {
                        position: 'top'
                    }
                },
                scales: {
                    r: {
                        angleLines: {
                            display: true
                        },
                        suggestedMin: 0,
                        suggestedMax: 10
                    }
                }
            }
        }));
    }

    renderOperationTypes(data) {
        const ctx = document.getElementById('operationsChart');
        if (!ctx) return;

        this.charts.set('operations', new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Text in Image', 'Image in Image', 'Video Steganography'],
                datasets: [{
                    data: data.operation_counts,
                    backgroundColor: [
                        'rgba(255, 107, 53, 0.8)',
                        'rgba(243, 156, 18, 0.8)',
                        'rgba(40, 167, 69, 0.8)'
                    ],
                    borderColor: [
                        'rgba(255, 107, 53, 1)',
                        'rgba(243, 156, 18, 1)',
                        'rgba(40, 167, 69, 1)'
                    ],
                    borderWidth: 2,
                    hoverOffset: 10
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: 'Operation Distribution'
                    }
                },
                cutout: '60%'
            }
        }));
    }

    processAlgorithmData(data) {
        // Process raw data for algorithm comparison
        // This is a simplified version - in real implementation, you'd process actual metrics
        return {
            curve25519: {
                speed: 9,
                security: 7,
                capacity: 8,
                reliability: 9,
                efficiency: 8
            },
            secp256r1: {
                speed: 7,
                security: 9,
                capacity: 7,
                reliability: 8,
                efficiency: 7
            }
        };
    }

    setupChartInteractions() {
        // Add click handlers for chart elements
        document.addEventListener('click', (e) => {
            if (e.target.closest('.chart-container')) {
                this.handleChartInteraction(e);
            }
        });
    }

    handleChartInteraction(event) {
        // Handle chart element clicks for detailed views
        console.log('Chart interaction:', event);
    }

    updateCharts() {
        this.loadOperationData();
    }

    destroy() {
        this.charts.forEach(chart => chart.destroy());
        this.charts.clear();
    }
}

// Initialize charts when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.performanceCharts = new PerformanceCharts();
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = PerformanceCharts;
}