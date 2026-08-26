"""Optional local Dash dashboard for visualizing anomalous packets.

dash/plotly are an optional extra ([dashboard]); imports are deferred into
launch() so the base package stays importable without them installed.
"""

import logging

logger = logging.getLogger(__name__)


def launch(anomalies):
    """Launch a local Dash app plotting anomalous packets. Blocks until closed."""
    import dash
    import plotly.express as px
    from dash import dcc, html

    logger.info("Starting dashboard. Open http://127.0.0.1:8050 in your browser.")
    try:
        app = dash.Dash(__name__)
        fig = px.scatter(anomalies, x="inter_arrival", y="size", title="Anomalous Packets")
        app.layout = html.Div([
            html.H1("NetForensicAI Dashboard"),
            dcc.Graph(figure=fig),
        ])
        app.run(debug=False)
    except Exception as e:
        logger.error(f"Error launching dashboard: {e}")
