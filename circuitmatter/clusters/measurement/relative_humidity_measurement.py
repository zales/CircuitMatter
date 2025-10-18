# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""Relative Humidity Measurement cluster."""

from circuitmatter import data_model


class RelativeHumidityMeasurement(data_model.Cluster):
    CLUSTER_ID = 0x0405
    REVISION = 3

    MeasuredValue = data_model.NumberAttribute(
        0x0000, signed=False, bits=16, default=0, X_nullable=True, P_reportable=True
    )
    MinMeasuredValue = data_model.NumberAttribute(
        0x0001, signed=False, bits=16, default=0, X_nullable=True
    )
    MaxMeasuredValue = data_model.NumberAttribute(
        0x0002, signed=False, bits=16, default=10000, X_nullable=True
    )
