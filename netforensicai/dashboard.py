"""Optional local Dash dashboard for visualizing anomalous packets.

dash/plotly are an optional extra ([dashboard]); imports are deferred into
launch() so the base package stays importable without them installed.
"""

import logging

logger = logging.getLogger(__name__)


def launch(anomaly_events):
    """Launch a local Dash app plotting anomaly Events. Blocks until closed.

    Plots the size/inter_arrival feature values that triggered each
    anomaly flag, which the pcap parser stashes in raw_event_reference
    since they aren't part of the common Event schema.
    """
    import dash
    import plotly.express as px
    from dash import dcc, html

    logger.info("Starting dashboard. Open http://127.0.0.1:8050 in your browser.")
    try:
        sizes = [e.raw_event_reference.get("size") for e in anomaly_events]
        inter_arrivals = [e.raw_event_reference.get("inter_arrival") for e in anomaly_events]

        app = dash.Dash(__name__)
        fig = px.scatter(
            x=inter_arrivals,
            y=sizes,
            labels={"x": "inter_arrival", "y": "size"},
            title="Anomalous Packets",
        )
        app.layout = html.Div([
            html.H1("NetForensicAI Dashboard"),
            dcc.Graph(figure=fig),
        ])
        app.run(debug=False)
    except Exception as e:
        logger.error(f"Error launching dashboard: {e}")
