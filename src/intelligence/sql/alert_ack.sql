UPDATE collector_alerts SET acknowledged=coalesce(acknowledged,max(opened,?1))
WHERE id=?2 AND session=?3 AND serial=?4 AND scope=?5 AND signal=?6 AND opened=?7;
