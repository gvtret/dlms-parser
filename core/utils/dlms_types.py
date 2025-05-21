# DLMS tag definitions
DLMS_TAGS = {
    # Application tags
    'AARQ': 0x60,
    'AARE': 0x61,
    'RLRQ': 0x62,
    'RLRE': 0x63,
    # Add more DLMS tags as needed
}

# DLMS data types
DLMS_DATA_TYPES = {
    0: "Null",
    1: "Array",
    2: "Structure",
    3: "Boolean",
    4: "Bit string",
    5: "Double-long",
    6: "Double-long-unsigned",
    9: "Octet string",
    10: "Visible string",
    # Add more data types as needed
}

def get_tag_name(tag_byte: int) -> str:
    tag_class = (tag_byte >> 6) & 0x03
    tag_number = tag_byte & 0x1f
    
    if tag_class == 1:  # Application
        for name, value in DLMS_TAGS.items():
            if value == tag_byte:
                return name
        return f"Application {tag_number}"
    elif tag_class == 2:  # Context-specific
        return f"Context {tag_number}"
    else:
        return f"Tag class {tag_class} number {tag_number}"